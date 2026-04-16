using Microsoft.Data.Sqlite;
using Snappass;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(6 * 31);
    options.Preload = true;
    options.IncludeSubDomains = true;
});
builder.Services.AddScoped<IMemoryStore, SqliteStore>();
builder.Services.AddSingleton<IDateTimeProvider, CurrentDateTimeProvider>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped(sp =>
{
    var databaseFilePath = "database.sqlite";
    var connectionString = $"Data Source={databaseFilePath}";
    return new SqliteConnection(connectionString);
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    context.Response.Headers.Append("Content-Security-Policy", "script-src 'self'; style-src 'self'; img-src 'self'");
    context.Response.Headers.Append("X-Xss-Protection", "1");
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
    await next();
});

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Share}/{action=Share}");
app.MapControllerRoute(
    name: "password",
    pattern: "pwd/{key}",
    defaults: new { controller = "Password", action = "Preview" });

app.Run();
