using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Snappass.NET.IntegrationTest;

public sealed class IntegrationTests : IClassFixture<SnappassFactory>
{
    private readonly SnappassFactory _factory;

    // Valid 32-char ID that passes the ^[A-Za-z0-9_-]{16,64}$ pattern.
    private const string ValidId = "AbCdEf1234567890AbCdEf1234567890";

    // Ciphertext well under the 100 000-byte limit.
    private static string SmallCiphertext() => new('x', 200);

    // Ciphertext one byte over the server-side 100 000-byte limit.
    private static string OversizeCiphertext() => new('x', 100_001);

    public IntegrationTests(SnappassFactory factory)
    {
        _factory = factory;
    }

    /// <summary>
    /// Creates an HttpClient whose default Origin header matches the TestServer
    /// Host (which is "localhost"). The Origin-check middleware compares the
    /// Origin authority to Request.Host.Value; TestServer exposes "localhost".
    /// </summary>
    private HttpClient CreateClientWithOrigin(string origin = "http://localhost")
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        client.DefaultRequestHeaders.Add("Origin", origin);
        return client;
    }

    /// <summary>
    /// Creates an HttpClient with NO Origin header — for testing the 403 path.
    /// </summary>
    private HttpClient CreateClientWithoutOrigin()
    {
        return _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
    }

    // -------------------------------------------------------------------------
    // Happy path
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Store_Exists_Consume_RoundTrip()
    {
        using var client = CreateClientWithOrigin();
        var ct = SmallCiphertext();

        // POST to store
        var storeResp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = ct, ttl = "Day" });
        Assert.Equal(HttpStatusCode.OK, storeResp.StatusCode);

        var stored = await storeResp.Content.ReadFromJsonAsync<IdResponse>();
        Assert.NotNull(stored?.Id);
        var id = stored!.Id;

        // GET exists → true
        var existsResp = await client.GetAsync($"/api/secrets/{id}/exists");
        Assert.Equal(HttpStatusCode.OK, existsResp.StatusCode);
        var existsBody = await existsResp.Content.ReadFromJsonAsync<ExistsResponse>();
        Assert.True(existsBody?.Exists);

        // POST consume → same ciphertext
        var consumeResp = await client.PostAsync($"/api/secrets/{id}/consume", null);
        Assert.Equal(HttpStatusCode.OK, consumeResp.StatusCode);
        var consumeBody = await consumeResp.Content.ReadFromJsonAsync<CiphertextResponse>();
        Assert.Equal(ct, consumeBody?.Ciphertext);
    }

    [Fact]
    public async Task Consume_IsOneShot_OverHttp()
    {
        using var client = CreateClientWithOrigin();

        var storeResp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = SmallCiphertext(), ttl = "Hour" });
        var stored = await storeResp.Content.ReadFromJsonAsync<IdResponse>();
        var id = stored!.Id;

        // First consume: OK
        var first = await client.PostAsync($"/api/secrets/{id}/consume", null);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        // Second consume: 404
        var second = await client.PostAsync($"/api/secrets/{id}/consume", null);
        Assert.Equal(HttpStatusCode.NotFound, second.StatusCode);
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Store_TooLarge_Returns400()
    {
        using var client = CreateClientWithOrigin();
        var resp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = OversizeCiphertext(), ttl = "Day" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Store_InvalidTtl_Returns400()
    {
        using var client = CreateClientWithOrigin();
        var resp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = SmallCiphertext(), ttl = "forever" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Store_InvalidViews_Returns400()
    {
        // 7 is not in the allowlist {1,2,3,5,10}.
        using var client = CreateClientWithOrigin();
        var resp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = SmallCiphertext(), ttl = "Day", views = 7 });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // -------------------------------------------------------------------------
    // Multi-view semantics (Doppler-style view limit)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Consume_MultiView_DecrementsThenExhausts()
    {
        using var client = CreateClientWithOrigin();
        var ct = SmallCiphertext();

        // Store with views = 3.
        var storeResp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = ct, ttl = "Day", views = 3 });
        Assert.Equal(HttpStatusCode.OK, storeResp.StatusCode);
        var stored = await storeResp.Content.ReadFromJsonAsync<IdResponse>();
        var id = stored!.Id;

        // Three successful consumes, same ciphertext each time.
        for (var i = 0; i < 3; i++)
        {
            var resp = await client.PostAsync($"/api/secrets/{id}/consume", null);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = await resp.Content.ReadFromJsonAsync<CiphertextResponse>();
            Assert.Equal(ct, body?.Ciphertext);
        }

        // Fourth attempt — row is gone.
        var exhausted = await client.PostAsync($"/api/secrets/{id}/consume", null);
        Assert.Equal(HttpStatusCode.NotFound, exhausted.StatusCode);

        // And /exists reflects that.
        var existsResp = await client.GetAsync($"/api/secrets/{id}/exists");
        var existsBody = await existsResp.Content.ReadFromJsonAsync<ExistsResponse>();
        Assert.False(existsBody?.Exists);
    }

    [Fact]
    public async Task Consume_UnlimitedViews_StaysAliveAcrossManyReads()
    {
        using var client = CreateClientWithOrigin();
        var ct = SmallCiphertext();

        // views = 0 is the sentinel for unlimited.
        var storeResp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = ct, ttl = "Day", views = 0 });
        Assert.Equal(HttpStatusCode.OK, storeResp.StatusCode);
        var stored = await storeResp.Content.ReadFromJsonAsync<IdResponse>();
        var id = stored!.Id;

        // Consume 5 times — all succeed, row stays alive.
        // (Rate limit on consume is 30/min, so 5 is well within budget.)
        for (var i = 0; i < 5; i++)
        {
            var resp = await client.PostAsync($"/api/secrets/{id}/consume", null);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = await resp.Content.ReadFromJsonAsync<CiphertextResponse>();
            Assert.Equal(ct, body?.Ciphertext);
        }

        // /exists still true after 5 reads.
        var existsResp = await client.GetAsync($"/api/secrets/{id}/exists");
        var existsBody = await existsResp.Content.ReadFromJsonAsync<ExistsResponse>();
        Assert.True(existsBody?.Exists);
    }

    [Fact]
    public async Task Store_ExtendedTtls_Accepted()
    {
        using var client = CreateClientWithOrigin();

        // Smoke-test the new TTL values — each one should round-trip.
        foreach (var ttl in new[] { "TwoDays", "ThreeDays", "TwoWeeks", "ThreeMonths" })
        {
            var resp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = SmallCiphertext(), ttl });
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
    }

    // -------------------------------------------------------------------------
    // Origin check
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Post_NoOrigin_Returns403()
    {
        // Use a client with no Origin header at all.
        using var client = CreateClientWithoutOrigin();
        var resp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = SmallCiphertext(), ttl = "Day" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Post_WrongOrigin_Returns403()
    {
        using var client = CreateClientWithOrigin("https://evil.example.com");
        var resp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = SmallCiphertext(), ttl = "Day" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Post_MatchingOrigin_Returns200()
    {
        // Origin: http://localhost matches TestServer's Host: localhost.
        using var client = CreateClientWithOrigin("http://localhost");
        var resp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = SmallCiphertext(), ttl = "Day" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // -------------------------------------------------------------------------
    // Security headers
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Get_ShareRoot_HasSecurityHeaders()
    {
        using var client = CreateClientWithoutOrigin();
        var resp = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        Assert.True(resp.Headers.TryGetValues("Content-Security-Policy", out var csp));
        Assert.StartsWith("default-src 'none'", csp!.First());

        Assert.True(resp.Headers.TryGetValues("X-Frame-Options", out var xfo));
        Assert.Equal("DENY", xfo!.First());

        Assert.True(resp.Headers.TryGetValues("Cache-Control", out var cc));
        Assert.Equal("no-store", cc!.First());

        Assert.True(resp.Headers.TryGetValues("Referrer-Policy", out var rp));
        Assert.Equal("no-referrer", rp!.First());
    }

    // -------------------------------------------------------------------------
    // Reveal page routing
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Get_Reveal_ValidId_Returns200()
    {
        using var client = CreateClientWithoutOrigin();
        // 32-char alphanumeric id — matches ^[A-Za-z0-9_-]{16,64}$
        var resp = await client.GetAsync($"/s/{ValidId}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Get_Reveal_InvalidId_Returns404()
    {
        using var client = CreateClientWithoutOrigin();
        // "bad" is only 3 chars — fails the ≥16 char requirement
        var resp = await client.GetAsync("/s/bad");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // -------------------------------------------------------------------------
    // Oversized raw body (Kestrel limit: 128 KiB)
    // -------------------------------------------------------------------------

    [Fact(Skip = "TestServer does not enforce Kestrel MaxRequestBodySize; the limit only applies to real Kestrel transport.")]
    public async Task Post_OversizedBody_Returns413()
    {
        // MaxRequestBodySize is configured via builder.WebHost.ConfigureKestrel(…)
        // and is enforced by the Kestrel transport layer. WebApplicationFactory
        // uses an in-process TestServer (not Kestrel), so MaxRequestBodySize is
        // never consulted and the request goes through regardless of body size.
        using var client = CreateClientWithOrigin();
        var oversized = new string('y', 130 * 1024);
        var resp = await client.PostAsJsonAsync("/api/secrets", new { ciphertext = oversized, ttl = "Day" });
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
    }

    // -------------------------------------------------------------------------
    // JSON response record types (private to this file — just enough to deserialize)
    // -------------------------------------------------------------------------

    private sealed record IdResponse(string Id);
    private sealed record ExistsResponse(bool Exists);
    private sealed record CiphertextResponse(string Ciphertext);
}
