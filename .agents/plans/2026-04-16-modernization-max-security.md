# Snappass.NET Modernization — Maximum Security

**Erstellt:** 2026-04-16
**Status:** In Umsetzung

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

### Phase 1 — Fundament
- [ ] `TargetFramework` → `net10.0`, Packages aktualisieren
- [ ] `<Nullable>enable</Nullable>` + `<ImplicitUsings>enable</ImplicitUsings>`
- [ ] `Startup.cs` → Top-Level Minimal Hosting in `Program.cs`
- [ ] `node_modules` aus Git entfernen, `.gitignore` aufräumen
- [ ] GitHub Actions: build + test, Dependabot

### Phase 2 — Security-Kern
- [ ] Neue Minimal-API-Endpunkte wie oben
- [ ] Alte Controller weg
- [ ] Frontend-Crypto-Modul in TypeScript (esbuild), AES-256-GCM via
      `SubtleCrypto`
- [ ] Key im URL-Fragment, niemals im Pfad/Query
- [ ] Proper Base64Url statt `Replace("-","+")`-Hack

### Phase 3 — Hardening
- [ ] Antiforgery-Token für Share-Submit
- [ ] `AddRateLimiter` (z. B. 10 Share/min, 30 Consume/min pro IP)
- [ ] Size-Limit auf Ciphertext (z. B. 64 KiB), TTL-Whitelist serverseitig
- [ ] CSP verschärfen: `default-src 'none'; script-src 'self';
      style-src 'self'; connect-src 'self'; img-src 'self'`
- [ ] jQuery + Clipboard.js raus → `navigator.clipboard`
- [ ] Passwortgenerator: `crypto.getRandomValues`, korrekte Länge,
      unbiased index

### Phase 4 — Storage-Layer
- [ ] Einheitliches Connection-Lifecycle (Factory oder Singleton + WAL)
- [ ] Schema-Init bei Startup
- [ ] DB-Pfad konfigurierbar
- [ ] Background-Cleanup alle 5 Min

### Phase 5 — Tests
- [ ] xUnit: Store (In-Memory SQLite), TTL-Ablauf, Consume-Idempotenz
- [ ] `WebApplicationFactory` für API-Integrationstests
- [ ] Playwright E2E: Happy Path + Assertion „Request-Body enthält nur
      Ciphertext, nie Plaintext"
- [ ] Security-Tests: Rate-Limit greift, Antiforgery greift, Consume ist
      one-shot

### Phase 6 — Deployment & Docs
- [ ] Dockerfile (chiseled), `docker-compose.yml`
- [ ] README mit expliziten Claims **und** Non-Claims
- [ ] `appsettings.Production.json` Template
- [ ] `/healthz`

## 4. Offene Fragen
- _(keine)_
