using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Snappass.NET.IntegrationTest;

/// <summary>
/// Custom factory that:
///   1. Points Storage:DatabasePath at a unique temp SQLite file per instance.
///   2. Provides a minimal wwwroot with share.html and reveal.html so
///      Results.File() resolves successfully without a real npm build.
/// </summary>
public sealed class SnappassFactory : WebApplicationFactory<Program>
{
    private readonly string _dbPath;
    private readonly string _webRoot;

    public SnappassFactory()
    {
        // Unique temp SQLite file — avoids the two-connection problem that
        // :memory: has (bootstrap connection ≠ scoped store connection).
        _dbPath = Path.Combine(Path.GetTempPath(), $"snappass-test-{Guid.NewGuid():N}.sqlite");

        // A temp directory containing minimal HTML stubs so Results.File succeeds.
        _webRoot = Path.Combine(Path.GetTempPath(), $"snappass-wwwroot-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_webRoot);
        File.WriteAllText(Path.Combine(_webRoot, "share.html"), "<!DOCTYPE html><html><body>share</body></html>");
        File.WriteAllText(Path.Combine(_webRoot, "reveal.html"), "<!DOCTYPE html><html><body>reveal</body></html>");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseWebRoot(_webRoot);

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Storage:DatabasePath"] = _dbPath,
                // Raise per-endpoint rate limits far above anything the suite
                // could hit. All TestServer clients share one rate-limit
                // partition (RemoteIpAddress is null → "unknown"), so the
                // production defaults would cross-contaminate tests.
                ["RateLimit:Share"] = "100000",
                ["RateLimit:Consume"] = "100000",
                ["RateLimit:Exists"] = "100000",
            });
        });

        // Run as Development so the app skips HTTPS redirect and returns
        // developer-friendly responses (no 500-swallowing exception handler).
        builder.UseEnvironment("Development");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing) return;

        // Clean up temp DB file.
        try { File.Delete(_dbPath); } catch { /* best-effort */ }
        try { File.Delete(_dbPath + "-wal"); } catch { /* best-effort */ }
        try { File.Delete(_dbPath + "-shm"); } catch { /* best-effort */ }

        // Clean up temp wwwroot.
        try { Directory.Delete(_webRoot, recursive: true); } catch { /* best-effort */ }
    }
}
