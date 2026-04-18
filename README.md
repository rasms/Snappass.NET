# Snappass.NET

A self-hosted one-shot password-sharing service where the server never sees
plaintext or the decryption key.

## How it works

- The sender enters a secret in the browser. AES-256-GCM encryption runs
  entirely in the browser via the Web Crypto API before anything is sent.
- The derived key is appended to the share URL as a fragment (`#key=...`).
  URL fragments are not transmitted to the server in HTTP requests.
- The server stores only the ciphertext, a TTL-derived expiry timestamp, and
  a random ID. No plaintext is ever transmitted or stored.
- When a recipient opens the link, the browser fetches the ciphertext and
  decrypts it locally using the key from the fragment.
- Each secret is consumed atomically on first retrieval (read-then-delete in a
  single SQLite transaction). Subsequent requests for the same ID return 404.
- Expired secrets are rejected on consume and purged by a background service.

## What this protects against

- **Server compromise with DB read access** — the server stores only ciphertext;
  the key is never transmitted.
- **Log leaks** — the key lives in the URL fragment, which is not included in
  HTTP request logs or `Referer` headers (`Referrer-Policy: no-referrer` is set).
- **Link-preview crawlers** — crawlers follow HTTP redirects but browsers do not
  send the fragment to the server, so crawlers never see the key.
- **Replay after consume** — atomic read+delete ensures one-shot delivery.
- **Replay after TTL** — expiry is checked on consume; a background service
  purges stale rows.

## What this does NOT protect against

- A malicious recipient forwarding the secret or the link before consuming it.
- A compromised sender or recipient device (keyloggers, screen capture, malicious
  browser extensions with access to page content).
- Phishing or typosquatted domains that serve a modified page.
- A malicious operator who modifies the JavaScript served to clients. The
  security model requires trusting the operator.
- Traffic analysis or metadata: the operator can observe source IPs, timing, and
  secret sizes (ciphertext length is visible).

## Local dev

Requirements: .NET 10 SDK and Node.js 20.

```sh
dotnet run --project Snappass.NET
dotnet test   # runs all 18 tests
```

The MSBuild targets in the `.csproj` run `npm install` and `npm run build`
automatically on first build.

## Deploy with docker-compose

```sh
docker compose up -d
```

Put the service behind a TLS-terminating reverse proxy. The container listens
on port 8080. The SQLite database is persisted in the `snappass-data` volume
mounted at `/data`.

The chiseled runtime image has no shell, so `docker exec` interactive sessions
are not available. Logs are available via `docker compose logs snappass`.

Example Caddy snippet:

```caddy
snappass.example.com {
    reverse_proxy localhost:8080
    health_uri /healthz
}
```

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `Storage__DatabasePath` | `database.sqlite` | Path to the SQLite database file |
| `ASPNETCORE_URLS` | `http://+:8080` (in Docker) | Kestrel listen address |
| `ASPNETCORE_ENVIRONMENT` | `Production` | ASP.NET Core environment name |
| `ASPNETCORE_FORWARDEDHEADERS_ENABLED` | unset | Set to `true` if using the env-var-only approach for forwarded headers; alternatively configure `KnownProxies` in code |

## Security caveats

- **Chiseled runtime**: the runtime container has no shell and no package
  manager. There is no in-container health probe; use an external check against
  `GET /healthz`.
- **Forwarded headers**: `X-Forwarded-For` / `X-Forwarded-Proto` processing is
  enabled in code but `KnownProxies` / `KnownNetworks` are left empty. You must
  configure trusted proxy addresses in `Program.cs` (or via
  `ASPNETCORE_FORWARDEDHEADERS_ENABLED`) before relying on remote-IP-based rate
  limiting behind a reverse proxy.
- **Rate limiter**: the fixed-window rate limiter is in-process. Horizontal
  scaling across multiple instances would require a shared backing store (e.g.
  Redis) — this is not currently implemented.
- **TLS**: Kestrel does not terminate TLS in the default configuration. TLS must
  be provided by the reverse proxy.
