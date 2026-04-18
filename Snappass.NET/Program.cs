using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Data.Sqlite;
using Snappass;

const int MaxCiphertextBytes = 100_000;
const long MaxRequestBytes = 128 * 1024;
var idPattern = new Regex("^[A-Za-z0-9_-]{16,64}$", RegexOptions.Compiled);

// Allowlist for the view-limit dropdown. Mirrors share.doppler.com's
// discrete choices but deliberately omits "unlimited": destructive read
// is a load-bearing part of our security model.
int[] allowedViews = [1, 2, 3, 5, 10];

var builder = WebApplication.CreateBuilder(args);

var dbPath = builder.Configuration["Storage:DatabasePath"] ?? "database.sqlite";
var connectionString = $"Data Source={dbPath}";

builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = MaxRequestBytes;
    options.AddServerHeader = false;
});

builder.Services.AddSingleton<IDateTimeProvider, CurrentDateTimeProvider>();
builder.Services.AddScoped<ISecretStore, SqliteStore>();
builder.Services.AddScoped(sp => new SqliteConnection(connectionString));

builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(6 * 31);
    options.Preload = true;
    options.IncludeSubDomains = true;
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    // The deploy wires up KnownProxies/KnownNetworks so only the trusted reverse
    // proxy can set X-Forwarded-*. Intentionally empty here.
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("share", ctx => Partition(ctx, permits: 10));
    options.AddPolicy("consume", ctx => Partition(ctx, permits: 30));
    options.AddPolicy("exists", ctx => Partition(ctx, permits: 60));

    static RateLimitPartition<string> Partition(HttpContext ctx, int permits) =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permits,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true,
            });
});

builder.Services.AddHostedService<ExpiredSecretCleaner>();

var app = builder.Build();

using (var bootstrap = new SqliteConnection(connectionString))
{
    bootstrap.Open();
    InitializeDatabase(bootstrap);
}

app.UseForwardedHeaders();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler(errorApp => errorApp.Run(async ctx =>
    {
        ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        await ctx.Response.WriteAsync("{\"error\":\"internal\"}");
    }));
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.Use(async (context, next) =>
{
    var h = context.Response.Headers;
    h.Append("Content-Security-Policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'");
    h.Append("X-Content-Type-Options", "nosniff");
    h.Append("X-Frame-Options", "DENY");
    h.Append("Referrer-Policy", "no-referrer");
    h.Append("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    h.Append("Cache-Control", "no-store");
    await next();
});

// Origin-Check: state-changing API calls must originate from our own host.
// Cheap CSRF defence even for JSON-only APIs — a text/plain form-POST bypasses
// the CORS preflight and would otherwise reach the endpoint.
app.Use(async (context, next) =>
{
    if (HttpMethods.IsPost(context.Request.Method) &&
        context.Request.Path.StartsWithSegments("/api"))
    {
        var origin = context.Request.Headers["Origin"].ToString();
        if (string.IsNullOrEmpty(origin) ||
            !Uri.TryCreate(origin, UriKind.Absolute, out var originUri) ||
            !string.Equals(originUri.Authority, context.Request.Host.Value, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
    }
    await next();
});

app.UseRateLimiter();

app.UseStaticFiles();

var sharePage = Path.Combine(app.Environment.WebRootPath, "share.html");
var revealPage = Path.Combine(app.Environment.WebRootPath, "reveal.html");

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));
app.MapGet("/", () => Results.File(sharePage, "text/html; charset=utf-8"));
app.MapGet("/s/{id}", (string id) =>
    idPattern.IsMatch(id)
        ? Results.File(revealPage, "text/html; charset=utf-8")
        : Results.NotFound());

var api = app.MapGroup("/api/secrets");

api.MapPost("/", (CreateSecretRequest req, ISecretStore store) =>
{
    if (string.IsNullOrWhiteSpace(req.Ciphertext))
        return Results.BadRequest(new { error = "ciphertext required" });
    if (req.Ciphertext.Length > MaxCiphertextBytes)
        return Results.BadRequest(new { error = "ciphertext too large" });
    if (!Enum.TryParse<TimeToLive>(req.Ttl, ignoreCase: true, out var ttl))
        return Results.BadRequest(new { error = "invalid ttl" });

    // Missing/null view count defaults to one-shot — same as pre-multi-view clients.
    var views = req.Views ?? 1;
    if (Array.IndexOf(allowedViews, views) < 0)
        return Results.BadRequest(new { error = "invalid views" });

    var id = Guid.NewGuid().ToString("N");
    store.Store(id, req.Ciphertext, ttl, views);
    return Results.Ok(new { id });
}).RequireRateLimiting("share");

api.MapGet("/{id}/exists", (string id, ISecretStore store) =>
{
    if (!idPattern.IsMatch(id)) return Results.NotFound();
    return Results.Ok(new { exists = store.Exists(id) });
}).RequireRateLimiting("exists");

api.MapPost("/{id}/consume", (string id, ISecretStore store) =>
{
    if (!idPattern.IsMatch(id)) return Results.NotFound();
    var ct = store.Consume(id);
    return ct is null ? Results.NotFound() : Results.Ok(new { ciphertext = ct });
}).RequireRateLimiting("consume");

app.Run();

static void InitializeDatabase(SqliteConnection connection)
{
    using var cmd = connection.CreateCommand();
    // WAL + secure_delete are persistent on-disk settings (SQLite 3.32+),
    // so one-shot at startup is enough. WAL cuts read/write contention;
    // secure_delete overwrites freed pages with zeros so deleted ciphertexts
    // don't linger in file slack.
    cmd.CommandText = @"
        PRAGMA journal_mode=WAL;
        PRAGMA secure_delete=ON;
        CREATE TABLE IF NOT EXISTS Secret (
            Id              TEXT PRIMARY KEY,
            CreatedDt       TEXT NOT NULL,
            ExpireDt        TEXT NOT NULL,
            Ciphertext      TEXT NOT NULL,
            RemainingViews  INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_secret_expire ON Secret(ExpireDt);";
    cmd.ExecuteNonQuery();

    // Migration for pre-multi-view databases: add RemainingViews if missing.
    // Idempotent via PRAGMA table_info — no migration framework needed for one column.
    using var info = connection.CreateCommand();
    info.CommandText = "PRAGMA table_info(Secret)";
    var hasViews = false;
    using (var reader = info.ExecuteReader())
    {
        while (reader.Read())
        {
            // table_info columns: cid, name, type, notnull, dflt_value, pk
            if (string.Equals(reader.GetString(1), "RemainingViews", StringComparison.OrdinalIgnoreCase))
            {
                hasViews = true;
                break;
            }
        }
    }
    if (!hasViews)
    {
        using var alter = connection.CreateCommand();
        alter.CommandText = "ALTER TABLE Secret ADD COLUMN RemainingViews INTEGER NOT NULL DEFAULT 1";
        alter.ExecuteNonQuery();
    }
}

public sealed record CreateSecretRequest(string Ciphertext, string Ttl, int? Views);

public partial class Program;
