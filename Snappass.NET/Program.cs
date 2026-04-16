using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Snappass;

const int MaxCiphertextBytes = 100_000;
var idPattern = new Regex("^[A-Za-z0-9_-]{16,64}$", RegexOptions.Compiled);

var builder = WebApplication.CreateBuilder(args);

var dbPath = builder.Configuration["Storage:DatabasePath"] ?? "database.sqlite";
var connectionString = $"Data Source={dbPath}";

builder.Services.AddSingleton<IDateTimeProvider, CurrentDateTimeProvider>();
builder.Services.AddScoped<ISecretStore, SqliteStore>();
builder.Services.AddScoped(sp => new SqliteConnection(connectionString));

builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(6 * 31);
    options.Preload = true;
    options.IncludeSubDomains = true;
});

var app = builder.Build();

using (var bootstrap = new SqliteConnection(connectionString))
{
    bootstrap.Open();
    EnsureSchema(bootstrap);
}

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
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
    await next();
});

app.UseStaticFiles();

var sharePage = Path.Combine(app.Environment.WebRootPath, "share.html");
var revealPage = Path.Combine(app.Environment.WebRootPath, "reveal.html");

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

    var id = Guid.NewGuid().ToString("N");
    store.Store(id, req.Ciphertext, ttl);
    return Results.Ok(new { id });
});

api.MapGet("/{id}/exists", (string id, ISecretStore store) =>
{
    if (!idPattern.IsMatch(id)) return Results.NotFound();
    return Results.Ok(new { exists = store.Exists(id) });
});

api.MapPost("/{id}/consume", (string id, ISecretStore store) =>
{
    if (!idPattern.IsMatch(id)) return Results.NotFound();
    var ct = store.Consume(id);
    return ct is null ? Results.NotFound() : Results.Ok(new { ciphertext = ct });
});

app.Run();

static void EnsureSchema(SqliteConnection connection)
{
    using var cmd = connection.CreateCommand();
    cmd.CommandText = @"
        CREATE TABLE IF NOT EXISTS Secret (
            Id          TEXT PRIMARY KEY,
            CreatedDt   TEXT NOT NULL,
            ExpireDt    TEXT NOT NULL,
            Ciphertext  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_secret_expire ON Secret(ExpireDt);";
    cmd.ExecuteNonQuery();
}

public sealed record CreateSecretRequest(string Ciphertext, string Ttl);

public partial class Program;
