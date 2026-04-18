# Snappass.NET

[![CI](https://github.com/rasms/Snappass.NET/actions/workflows/ci.yml/badge.svg)](https://github.com/rasms/Snappass.NET/actions/workflows/ci.yml)
[![Container](https://github.com/rasms/Snappass.NET/actions/workflows/release.yml/badge.svg)](https://github.com/rasms/Snappass.NET/actions/workflows/release.yml)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Container: GHCR](https://img.shields.io/badge/Container-ghcr.io-2496ED)](https://github.com/rasms/Snappass.NET/pkgs/container/snappass.net)

A self-hosted, one-shot password-sharing service where the server never sees
plaintext or the decryption key. A .NET 10 port of Pinterest's
[SnapPass](https://github.com/pinterest/snappass), rewritten with a
client-side-crypto threat model.

## Table of contents

- [Why](#why)
- [How it works](#how-it-works)
- [Security model](#security-model)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Development](#development)
- [Testing](#testing)
- [Deployment](#deployment)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## Why

Password-sharing tools that encrypt on the server are only as trustworthy as
the server itself. If the process memory, database, or logs leak, every secret
in flight at that moment leaks with them. Snappass.NET does the encryption in
the browser and keeps the decryption key out of every HTTP message, so even a
complete database read-out does not reveal any secret.

## How it works

1. The sender opens the share page. The browser generates an AES-256-GCM key
   via the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
2. The sender picks a TTL (up to one month) and a view limit (1 / 2 / 3 / 5 /
   10). Whichever bound is hit first destroys the secret.
3. The browser encrypts the plaintext locally and `POST`s only the ciphertext
   to the server, which stores `(id, ciphertext, expires_at, remaining_views)`.
4. The share URL takes the form `https://host/s/<id>#<key>`. The
   [URL fragment](https://developer.mozilla.org/en-US/docs/Web/API/URL/hash)
   after `#` is never sent in any HTTP request, so neither the server nor any
   proxy/log/link-preview crawler sees the key.
5. The recipient opens the link. The reveal page reads the key from
   `location.hash`, fetches the ciphertext, and decrypts it locally.
6. Retrieval is atomic: in a single SQLite transaction the server either
   decrements `remaining_views` and returns the ciphertext, or — on the final
   permitted view — deletes the row and returns the ciphertext. A background
   service additionally purges expired rows every five minutes.

## Security model

### Claims

| Threat                                                   | Mitigation                                                                                   |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Server compromise with full database read                | Server stores only AES-256-GCM ciphertext; the key is never transmitted                      |
| Log leaks (application, reverse-proxy, WAF)              | Key lives in the URL fragment, which is not sent in requests or the `Referer` header         |
| Link-preview crawlers (Slack, Teams, iMessage, …)        | Crawlers fetch the URL but not the fragment; they never see the key                          |
| Replay after view limit                                  | Atomic read-then-decrement (or delete on final view) in a single SQLite transaction          |
| Replay after TTL                                         | Per-consume expiry check plus background purge; `secure_delete=ON` zero-wipes freed pages    |
| Brute force on secret IDs                                | 128-bit random IDs (`Guid.NewGuid().ToString("N")`); endpoints are rate-limited per IP       |
| Cross-site request forgery                               | `Origin` header match required on every state-changing `POST`; strict CSP; no same-origin cookies |
| Oversized or abusive payloads                            | Kestrel `MaxRequestBodySize = 128 KiB`; per-endpoint rate limiter                            |

### Non-claims

Snappass.NET deliberately does **not** defend against:

- A malicious recipient forwarding the secret or the link before consuming it.
- Compromised sender or recipient devices (keyloggers, screen capture, malicious
  browser extensions with DOM access).
- Phishing or typosquatted domains that serve a modified page.
- A malicious operator who modifies the JavaScript served to clients —
  this tool requires trusting the operator.
- Traffic analysis: the operator sees source IPs, timing, and ciphertext size.

## Quick start

Requirements: Docker and Docker Compose.

```sh
git clone https://github.com/rasms/Snappass.NET.git
cd Snappass.NET
docker compose up -d
```

The service listens on `http://localhost:8080`. Put it behind a TLS-terminating
reverse proxy before exposing it publicly.

Pre-built images are published to GitHub Container Registry on every push to
`main` and on tagged releases:

```sh
docker pull ghcr.io/rasms/snappass.net:latest
```

## Configuration

All configuration is via environment variables (ASP.NET Core's standard
`__` delimiter maps to nested JSON).

| Variable                             | Default                  | Description                                                                 |
| ------------------------------------ | ------------------------ | --------------------------------------------------------------------------- |
| `Storage__DatabasePath`              | `database.sqlite`        | Path to the SQLite database file                                            |
| `ASPNETCORE_URLS`                    | `http://+:8080` (Docker) | Kestrel bind address                                                        |
| `ASPNETCORE_ENVIRONMENT`             | `Production`             | `Development` enables the developer exception page and skips HTTPS redirect |
| `ASPNETCORE_FORWARDEDHEADERS_ENABLED`| unset                    | Set to `true` behind a trusted reverse proxy                                |
| `Logging__LogLevel__Default`         | `Warning` (Production)   | Minimum log level                                                           |

### View-limit choices

| Value | Meaning                                                           |
| ----- | ----------------------------------------------------------------- |
| 1     | One-shot (default) — atomic read-then-delete, classic SnapPass    |
| 2     | Two permitted reads, then delete                                  |
| 3     | Three permitted reads, then delete                                |
| 5     | Five permitted reads, then delete                                 |
| 10    | Ten permitted reads, then delete                                  |

There is deliberately no "unlimited" option — destructive read is a
load-bearing part of the security model. The server does not expose the
remaining view count to the recipient, to avoid leaking consumption state
to anyone who holds the URL.

### Rate-limit defaults

| Endpoint                  | Limit         |
| ------------------------- | ------------- |
| `POST /api/secrets`       | 10/min per IP |
| `POST /api/secrets/:id/consume` | 30/min per IP |
| `GET /api/secrets/:id/exists`   | 60/min per IP |

Limits are per-IP fixed windows, implemented in-process. Horizontal scaling
across instances would require a shared backing store.

## Development

Requirements:

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [Node.js 20](https://nodejs.org/) (only for the frontend build)

```sh
dotnet run --project Snappass.NET
```

The `Snappass.NET.csproj` wires `npm install` and `npm run build` into
`dotnet build` via MSBuild targets, so a single `dotnet run` also builds the
TypeScript and Tailwind bundles.

Frontend sources live in `Snappass.NET/src/` (TypeScript) and
`Snappass.NET/Styles/` (Tailwind input). Built artifacts go to
`Snappass.NET/wwwroot/js/` and `Snappass.NET/wwwroot/css/` and are
`.gitignore`d.

## Testing

```sh
dotnet test
```

- **`Snappass.NET.UnitTest`** — 10 tests covering the store, TTL expiry,
  one-shot and multi-view semantics, and background-purge behaviour.
- **`Snappass.NET.IntegrationTest`** — 12 tests (+1 skip) driving the full
  HTTP pipeline through `WebApplicationFactory<Program>`: Origin checks,
  validation, security headers, routing, multi-view round-trips.

The `Post_OversizedBody_Returns413` integration test is skipped because
`TestServer` is in-process and bypasses Kestrel's `MaxRequestBodySize`; the
413 guard only fires on real Kestrel and is smoke-tested manually.

## Deployment

### Docker Compose

The provided `docker-compose.yml` applies several hardening flags:

- `read_only: true` — the container root filesystem is immutable at runtime
- `tmpfs: [/tmp]` — writable scratch only where needed
- `cap_drop: [ALL]` — no Linux capabilities
- `security_opt: [no-new-privileges:true]` — setuid and friends blocked
- Named volume at `/data` for SQLite persistence
- Non-root `app` user (default in the chiseled runtime image)

The chiseled runtime image has no shell, curl, or wget, so in-container
healthchecks are not available. Probe `GET /healthz` from your reverse
proxy or orchestrator instead:

```caddy
snappass.example.com {
    reverse_proxy localhost:8080
    health_uri /healthz
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto {scheme}
}
```

If you rely on forwarded headers for rate-limit partitioning, configure
`KnownProxies` / `KnownNetworks` in `Program.cs` — the defaults are
intentionally empty to avoid trusting arbitrary proxies.

### Container image

Images are published to `ghcr.io/rasms/snappass.net` with the following tags:

| Tag             | Source                        |
| --------------- | ----------------------------- |
| `latest`        | latest push to `main`         |
| `main`          | same as `latest`              |
| `vX.Y.Z`        | semver-tagged release         |
| `sha-<7-char>`  | specific commit               |

Images are built for `linux/amd64` and `linux/arm64`.

## Architecture

- **Server** — ASP.NET Core 10 Minimal API. Three endpoints under
  `/api/secrets` plus two HTML shells (`/` and `/s/{id}`).
- **Storage** — SQLite with `journal_mode=WAL` and `secure_delete=ON`. A
  `BackgroundService` purges expired rows every five minutes.
- **Frontend** — TypeScript compiled with esbuild, Tailwind CSS 3.4. No
  jQuery, no Bootstrap, no runtime framework.
- **Hardening** — strict CSP (`default-src 'none'`), HSTS with one-year
  `max-age`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`, `Server` header suppressed.

## Contributing

Issues and pull requests are welcome. Before submitting:

```sh
dotnet build --configuration Release
dotnet test  --configuration Release
```

Keep commits focused and include a short `why` in the message.

## License

MIT. See [LICENSE](LICENSE).

Derived from [Pinterest SnapPass](https://github.com/pinterest/snappass)
(MIT) and the original .NET port by
[generateui/Snappass.NET](https://github.com/generateui/Snappass.NET) (MIT).
