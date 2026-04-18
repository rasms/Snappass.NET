# Snappass.NET Modernization — Maximum Security

**Erstellt:** 2026-04-16
**Status:** Abgeschlossen (Phase 1–8)

## Ziel

Snappass.NET auf einen aktuellen, hart gehärteten Stand bringen mit dem
Sicherheitsversprechen, dass der **Server zu keinem Zeitpunkt Zugriff auf den
Klartext eines Secrets hat**.

## 1. Threat-Modell

### Verteidigen gegen
- Abhören im Transit (TLS + clientseitige Krypto)
- **Server-Kompromittierung mit vollem DB-Lesezugriff** — Angreifer soll
  keine Secrets entschlüsseln können
- Logging-Leaks (Server-, Reverse-Proxy-, WAF-Logs): dürfen keinen
  Decryption-Key enthalten
- Browser-History, Referrer, Link-Preview-Crawler (Slack / Teams / iMessage,
  die URLs vorab fetchen)
- Replay nach Abruf (Read-Once) und nach TTL
- Brute-Force auf Storage-IDs

### Kein primäres Ziel
- Bösartiger legitimer Empfänger (kann Secret weitergeben)
- Kompromittiertes Endgerät
- Phishing / gefälschte Domains
- Anonymität gegenüber dem Server-Betreiber (IPs werden gesehen)

### Sicherheitsversprechen
- Server hält Secrets ausschließlich als AES-256-GCM-Ciphertext
- Decryption-Key verlässt den Sender-Browser nur im URL-**Fragment**
  (`#…`), geht nie in einem HTTP-Request an den Server
- Jeder Secret-Abruf ist atomar destruktiv (gelesen = gelöscht)

## 2. Zielarchitektur

### Server (.NET 10 Minimal API)
- `POST /api/secrets` — nimmt fertigen Ciphertext + TTL, gibt Storage-ID
  zurück
- `GET /api/secrets/{id}/exists` — nur Existenzcheck für Preview-Seite
  (kein Konsum)
- `POST /api/secrets/{id}/consume` — atomares Lesen+Löschen, gibt
  Ciphertext
- Statische Shell-Seiten für Share/Reveal

### Client (Browser, WebCrypto API)
- **Share:** AES-256-GCM-Key clientseitig generieren, Plaintext lokal
  verschlüsseln, Ciphertext posten, URL mit Key im Fragment anzeigen
- **Reveal:** Key aus `location.hash` lesen, Ciphertext per POST holen,
  lokal entschlüsseln

### Storage
- **SQLite** bleibt — kleinere Angriffsfläche als Postgres/MySQL (kein
  Netzwerk-Daemon), ausreichend für erwartete Last
- WAL-Mode, `secure_delete=ON`
- Schema-Init beim Start
- `IHostedService` für periodischen Cleanup abgelaufener Einträge

### Container
- Multi-stage Dockerfile mit
  `mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled` als Runtime
  (minimal, ohne Shell)
- Non-root User
- SQLite-Datei auf separatem Volume

## 3. Phasen

### Phase 1 — Fundament ✓
- [x] `TargetFramework` → `net10.0`, Packages aktualisieren
- [x] `<Nullable>enable</Nullable>` + `<ImplicitUsings>enable</ImplicitUsings>`
- [x] `Startup.cs` → Top-Level Minimal Hosting in `Program.cs`
- [x] `node_modules` aus Git entfernen, `.gitignore` aufräumen
- [x] GitHub Actions: build + test, Dependabot
- [x] `SqliteStore` Open/Close-Bug gefixt (war Test-Blocker)

### Phase 2 — Security-Kern ✓
- [x] Neue Minimal-API-Endpunkte wie oben
- [x] Alte Controller/Views/Models/Encryption.cs weg
- [x] Frontend-Crypto-Modul in TypeScript (esbuild), AES-256-GCM via
      `SubtleCrypto`
- [x] Key im URL-Fragment, niemals im Pfad/Query
- [x] Proper Base64Url (kein `Replace("-","+")`-Hack mehr)
- [x] Strenge CSP: `default-src 'none'; script-src 'self'; style-src 'self';
      connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'self';
      frame-ancestors 'none'`
- [x] jQuery + Clipboard.js raus → `navigator.clipboard`
- [x] Passwortgenerator: `crypto.getRandomValues` mit Rejection-Sampling
      (unbiased)
- [x] Size-Limit auf Ciphertext (100 KB, serverseitig), TTL-Whitelist
      serverseitig (Enum.TryParse)

### Phase 3 — Hardening ✓
- [x] `AddRateLimiter` pro IP: 10 Share/min, 30 Consume/min, 60 Exists/min
- [x] Origin-Check-Middleware für `POST /api/*` (403 bei Missing/Mismatch)
- [x] Kestrel `MaxRequestBodySize = 128 KiB`, Body > Limit → 413
- [x] `AddServerHeader = false` (kein `Server:` Header mehr)
- [x] `Cache-Control: no-store` global gesetzt
- [x] Generischer JSON-500-Handler in Production (`UseExceptionHandler`)
- [x] `UseForwardedHeaders` vorbereitet für Reverse-Proxy-Deployment
- [x] HTTPS-Redirect nur in Production (bereits aus Phase 2)

### Phase 4 — Storage-Layer ✓
- [x] `PRAGMA journal_mode=WAL` + `PRAGMA secure_delete=ON` beim Startup
      (SQLite 3.32+ persistiert beide im DB-Header; secure_delete=2/FAST
      überschreibt freigegebene Pages mit Nullen vor Re-Use)
- [x] Schema-Init beim Startup (aus Phase 1 erhalten)
- [x] DB-Pfad konfigurierbar via `Storage:DatabasePath`
- [x] `ExpiredSecretCleaner` als `BackgroundService`: 30 s Startdelay,
      dann alle 5 min `DELETE FROM Secret WHERE ExpireDt <= @now`
- [x] `ISecretStore.PurgeExpired` + zwei Tests

### Phase 5 — Tests ✓
- [x] xUnit Unit-Tests (aus Phase 2/4 erweitert: 8 Tests)
- [x] `WebApplicationFactory` Integrationstests (neues Projekt
      `Snappass.NET.IntegrationTest`, 10 Tests + 1 skip):
      - Happy Path (Store/Exists/Consume Round-Trip)
      - Consume one-shot über HTTP
      - Ciphertext zu groß → 400
      - Invalid TTL → 400
      - Origin missing/falsch/matching → 403/403/200
      - Security-Header auf HTML-Response (CSP/XFO/Cache-Control/RP)
      - Reveal-Routing (valid 200, invalid 404)
      - `Post_OversizedBody_Returns413` skipped (TestServer umgeht
        Kestrel-Transport; 413 nur auf echtem Kestrel)
- [ ] _Offen:_ Rate-Limiter-Integrationstest — Limiter-State ist
      prozessglobal, braucht Refactor auf overridable Policy-Factory
- [ ] _Nicht gemacht:_ Playwright E2E mit Plaintext-Leak-Assertion
      (bewusst verschoben, nicht Phase-5-kritisch)

### Phase 6 — Deployment & Docs ✓
- [x] `GET /healthz` → `{"status":"ok"}`
- [x] Multi-stage Dockerfile: SDK+Node builder → chiseled aspnet
      Runtime (`mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled`,
      non-root `app` user)
- [x] `.dockerignore` (bin/obj/node_modules/tests/git/.agents raus)
- [x] `docker-compose.yml` mit `read_only`, `cap_drop: [ALL]`,
      `no-new-privileges`, named Volume für SQLite, Healthcheck extern
      weil chiseled keine Shell/curl/wget hat
- [x] `appsettings.Production.json` Template (`/data/database.sqlite`,
      Log-Level Warning)
- [x] `README.md` mit expliziten Claims / Non-Claims, Dev-Setup,
      Docker-Compose-Deploy, Config-Tabelle, Security-Caveats
- [ ] _Offen:_ `docker build` nicht verifiziert (Docker-Daemon im Dev
      nicht gestartet) — CI wird das abdecken, wenn wir einen Build-Job
      ergänzen

### Phase 7 — Multi-View Secrets ✓

Angelehnt an [share.doppler.com](https://share.doppler.com/): zusätzlich zur
TTL eine Obergrenze an Öffnungen. Was zuerst erreicht ist (Zeit oder Views),
beendet das Secret.

- [x] Schema: Spalte `RemainingViews INTEGER NOT NULL DEFAULT 1`, idempotente
      Migration über `PRAGMA table_info`
- [x] `ISecretStore.Store(id, ciphertext, ttl, views)` — neuer Parameter
- [x] `SqliteStore.Consume` atomar: im selben Transaction-Scope entweder
      `UPDATE SET RemainingViews = RemainingViews - 1` oder `DELETE` (wenn
      der letzte View aufgebraucht ist); expired/unknown unverändert
- [x] API `POST /api/secrets` akzeptiert `views` (int), serverseitige
      Allowlist `{1, 2, 3, 5, 10}`, Default 1 → kein Verhaltenswechsel
      für bestehende Clients
- [x] **Bewusst kein** `remainingViews` in der `/exists`-Response:
      minimiert Informationsleakage gegenüber Dritten, die die URL
      fingen würden
- [x] **Bewusst kein** Unlimited-Option: destruktiver Read bleibt Teil
      der Zusage
- [x] Frontend: zweites Dropdown auf der Share-Seite, Result-Text
      passt sich an (one-shot vs. N-shot), Reveal-Seite-Wording
      nicht mehr auf "nur einmal" festgenagelt
- [x] Unit-Tests: multi-view Consume dekrementiert, letzter Consume löscht
- [x] Integration-Test: 3-View-Round-Trip, vierter Consume → 404
- [x] README How-it-works + Config-Tabelle aktualisiert

### Phase 8 — Dropdown-Parität mit Doppler + Branding ✓

- [x] TTL-Enum erweitert: `TwoDays`, `ThreeDays`, `TwoWeeks`, `ThreeMonths`
      (matcht Dopplers 1d/2d/3d/1w/2w/1m/3m, plus unser `Hour` für
      kurzlebiges)
- [x] View-Allowlist: zusätzlich `20`, `50`, und Sentinel `0` = unlimited.
      `RemainingViews = 0` in der DB wird von Consume als Unlimited-Flag
      interpretiert (weder Update noch Delete; TTL greift weiterhin als
      harte Obergrenze). Kein Schema-Change nötig.
- [x] Logo: Vorhängeschloss mit Blitz-Bolzen innen, flat/indigo
      (`#4f46e5`), inline SVG in `wwwroot/logo.svg`. Alter
      `logoipsum-262.svg`-Platzhalter entfernt.
- [x] Wordmark "Snappass.NET" neben dem Logo, auf share- und reveal-Seite
- [x] Favicon: SVG-Link für moderne Browser, `favicon.ico` bleibt als
      Fallback
- [x] Tests ergänzt: unlimited (views=0) bleibt nach N Consumes bestehen,
      wird erst durch TTL gelöscht

## 4. Offene Fragen
- _(keine)_
