# What is done

Status as of 2026-05-19. See [Plan.md](Plan.md) for the full roadmap.

## Milestone 0 — Skeleton ✅

End-to-end verified locally on macOS via Docker Compose. The user smoke-tested `/healthz`, `bootstrap-admin`, and `/v1/auth/login` successfully (user `tower@raumdock.org`, id=1, role=admin).

### Repo scaffold

- `go.mod` (Go 1.23, module `github.com/raumdock/rdoc-camhub`) + `go.sum`
- `.gitignore`, [README.md](README.md), [CLAUDE.md](CLAUDE.md) (working agreements)
- Directory layout: `cmd/camhub/`, `internal/{config,db,migrations,auth,httpapi}/`, `web/templates/`, `deploy/`

### Build & deploy

- [deploy/Dockerfile](deploy/Dockerfile) — multi-stage `golang:1.23-alpine` → `FROM scratch`, non-root user, ~15 MB image
- [docker-compose.yml](docker-compose.yml) — `postgres:16-alpine` + `camhub` + `caddy:2-alpine`, Docker secrets for password / DSN / session key, named volumes
- [deploy/Caddyfile](deploy/Caddyfile) — local-dev `:80` proxy; production hostnames commented placeholders
- [Makefile](Makefile) — `build`, `test`, `lint`, `run`, `stop`, `image`, `migrate-up`, `migrate-down`, `secrets-init`, `clean`
- [.github/workflows/ci.yml](.github/workflows/ci.yml) — `go vet`, `staticcheck`, `go test -race` against a Postgres service, image build

### Config

- [internal/config/config.go](internal/config/config.go) — env-driven, with `CAMHUB_*_FILE` variants preferred (Docker-secrets-friendly). Validates session key ≥ 32 bytes. `slog` level parsing.

### Database

- [internal/db/db.go](internal/db/db.go) — pgx connection pool, `Migrate` / `MigrateDown` via embedded goose
- [internal/db/users.go](internal/db/users.go), [sessions.go](internal/db/sessions.go) — stores for `users` and `sessions`
- [internal/migrations/00001_init.sql](internal/migrations/00001_init.sql) + [embed.go](internal/migrations/embed.go) — schema for `users`, `sessions`, `api_tokens`, `enrollment_tokens` with indexes

### Auth primitives

- [internal/auth/password.go](internal/auth/password.go) — Argon2id (64 MiB, t=2, p=2, 32-byte key, 16-byte salt), `HashPassword` + `VerifyPassword`
- [internal/auth/session.go](internal/auth/session.go) — 32-byte random hex session IDs, 7-day TTL, cookie name constant

### HTTP API

- [internal/httpapi/router.go](internal/httpapi/router.go) — chi router with `RequestID`, structured logging, `Recoverer`. (Trust-aware IP middleware replaced chi's `RealIP` in M0.5 PR-S1.)
- [internal/httpapi/health.go](internal/httpapi/health.go) — `GET /healthz` with DB ping, returns 503 if DB is down
- [internal/httpapi/auth.go](internal/httpapi/auth.go) — `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/auth/me`; HttpOnly + SameSite=Lax cookies; dummy Argon2 verify on unknown-email to flatten timing
- [internal/httpapi/middleware.go](internal/httpapi/middleware.go) — request logging
- [internal/httpapi/json.go](internal/httpapi/json.go) — `writeJSON` / `writeError` helpers

### CLI

- [cmd/camhub/main.go](cmd/camhub/main.go) — `serve` (default), `migrate up|down`, `version`, `help`, signal-aware graceful shutdown
- [cmd/camhub/bootstrap.go](cmd/camhub/bootstrap.go) — `bootstrap-admin --email --password`, idempotent migrate before insert, min 12-char password

### Plan updates

- [Plan.md](Plan.md) §11 updated to reflect Postgres choice (was SQLite-recommended)
- [Plan.md](Plan.md) §15 Q2 (SQLite vs Postgres) marked resolved

## Decisions made during M0

| Decision | Why |
|---|---|
| Postgres from day 1 (not SQLite) | User choice; keeps multi-instance / richer audit options open |
| Auto-suffix on DNS name conflict (`livingroom-2`) | User choice; never blocks enrollment |
| Random-hex session IDs in a DB table (not JWTs) | Simpler revocation, no key rotation surface for the cookie path |
| Hex-encoded postgres password in `secrets-init` | Base64 contains `+`, which broke DSN URL parsing |
| File-based secrets via `*_FILE` env vars | Plan §10 ("No secrets in env or compose") |

## Milestone 0.5 — Security baseline (in progress)

Source: [Securityfindings.md](Securityfindings.md), tracked as PR-S1..PR-S7 in [Plan.md](Plan.md) §16. M1 cannot start until SEC-001..SEC-004 + SEC-006 are closed.

### ✅ PR-S1 — Cookie security + proxy trust (SEC-001, SEC-006, SEC-008)

- [internal/config/config.go](internal/config/config.go) — new fields `CookieSecure` (default `true`), `CookieDomain`, `TrustedProxies []netip.Prefix`. New env vars: `CAMHUB_COOKIE_DOMAIN`, `CAMHUB_DEV_INSECURE_COOKIE`, `CAMHUB_TRUSTED_PROXIES`. CIDR parsing via `netip.ParsePrefix`.
- [internal/httpapi/cookie.go](internal/httpapi/cookie.go) — new `SessionCookieConfig` with `New`, `NewClearing`, `NewSession`. Cookie attributes (HttpOnly, SameSite=Lax, Secure, Domain, Path) now come from server config — never from `r.TLS`.
- [internal/httpapi/trusted_ip.go](internal/httpapi/trusted_ip.go) — replaces chi `RealIP`. Default-deny: empty trusted list ⇒ `X-Forwarded-For` / `X-Real-IP` ignored. Walks XFF right-to-left, stops at first untrusted hop. Resolved IP exposed via `ClientIP(ctx context.Context) netip.Addr`.
- [internal/httpapi/router.go](internal/httpapi/router.go) — new `Options{Cookies, TrustedProxies}` for `New()`. New optional `LoginRateLimiter` middleware slot.
- [internal/httpapi/auth.go](internal/httpapi/auth.go) — both `Secure: r.TLS != nil` sites swapped for `s.Cookies.NewSession(…)` / `NewClearing(…)`. `RemoteAddr` → `ClientIP(ctx)` for `sessions.Create`.
- [deploy/Caddyfile.prod](deploy/Caddyfile.prod) — new production-only Caddyfile. HSTS preload, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, baseline CSP, strips upstream `Server` header. Defines `api.raumdock.org` + `app.raumdock.org`.
- [cmd/camhub/main.go](cmd/camhub/main.go) — startup log now includes `cookie_secure` and `trusted_proxies` count; loud WARN when `cookie_secure=false`.
- [docker-compose.yml](docker-compose.yml) — pre-trusts Docker bridge ranges (`172.16.0.0/12,10.0.0.0/8,192.168.0.0/16`) so Caddy's `X-Forwarded-For` reaches the limiter. `CAMHUB_DEV_INSECURE_COOKIE=1` for the local plain-HTTP setup.

### ✅ PR-S2 — Login hardening (SEC-002)

- [internal/httpapi/auth.go](internal/httpapi/auth.go) — login body wrapped in `http.MaxBytesReader` (4 KiB → 413 `body_too_large`). `DisallowUnknownFields` on JSON decoder. Pre-Argon2 caps: email ≤ 320, password ≤ 1024 → 400 *before* hashing. Dummy-hash branch for unknown email preserved (timing parity).
- [internal/httpapi/rate_limit.go](internal/httpapi/rate_limit.go) — new `LoginRateLimiter(RateLimitConfig)` middleware. Token-bucket per `ClientIP`, configurable via `CAMHUB_LOGIN_RATE_PER_IP` (default 10) and `CAMHUB_LOGIN_RATE_WINDOW_SECS` (default 60). Lazy bucket GC after `window` idle. Returns 429 + `Retry-After: 60`. Single-process only (Redis-ready when we scale horizontally). **Fail-closed** on missing `ClientIP` (503 `client_ip_unknown`).
- [cmd/camhub/main.go](cmd/camhub/main.go) — wires the limiter onto `POST /v1/auth/login` using the configured thresholds.

### ✅ Review fixes applied after self-review (same day)

- **Comment honesty** ([rate_limit.go:28-36](internal/httpapi/rate_limit.go#L28-L36)): the "fail closed" comment now matches the implementation — invalid `ClientIP` returns 503 `client_ip_unknown` instead of silently bypassing the limiter.
- **Configurable rate limit**: hardcoded `10 / 60s` replaced with `CAMHUB_LOGIN_RATE_PER_IP` / `CAMHUB_LOGIN_RATE_WINDOW_SECS` (config + README).
- **Handler-level tests** (4 new tests in [internal/httpapi/auth_test.go](internal/httpapi/auth_test.go)) — covers the three plan-acceptance gaps from the review:
  - `TestLogin_BodyTooLarge_Returns413_BeforeDB` — 5 KiB body → 413 `body_too_large`, DB never touched.
  - `TestLogin_PasswordTooLong_Returns400_BeforeArgon2AndBeforeDB` — 1025-char password → 400 before hashing, asserts wall-clock < 25 ms to prove Argon2id never ran.
  - `TestLogin_EmailTooLong_Returns400_BeforeDB` — > 320-char email → 400 before DB.
  - `TestLogin_ErrorParity_UnknownEmail_vs_WrongPassword` — byte-identical response bodies and status codes; defence against account enumeration.
- **Tiny interface refactor** ([internal/httpapi/router.go](internal/httpapi/router.go)): `Server.Users` is now `UserLookup`, `Server.Sessions` is `SessionWriter`. `*db.UserStore` / `*db.SessionStore` continue to satisfy them; the only consumer-visible change is that tests can now inject stubs without standing up Postgres.

### Tests added in M0.5 so far

[internal/httpapi/](internal/httpapi/) — 20 tests, 13 subcases, all passing with `-race`:

- [cookie_test.go](internal/httpapi/cookie_test.go) — cookie flag invariants (HttpOnly, SameSite=Lax, Secure follows config) in prod, prod-with-domain, dev-insecure; clearing-cookie keeps flags asserted.
- [trusted_ip_test.go](internal/httpapi/trusted_ip_test.go) — XFF / RealIP trust matrix: empty list ignores XFF, untrusted peer ignores XFF, trusted peer uses XFF, chain-walking stops at first untrusted hop, all-trusted chain returns innermost proxy, X-Real-IP fallback, malformed XFF safety, IPv6 peer.
- [rate_limit_test.go](internal/httpapi/rate_limit_test.go) — nil-when-disabled, budget exhaustion → 429, per-IP isolation, refill over window.
- [auth_test.go](internal/httpapi/auth_test.go) — handler-level: 413 body-too-large before DB; 400 length-cap before Argon2id (timing-asserted); 400 email-too-long before DB; byte-identical error parity for unknown-email vs wrong-password.

Remaining auth tests (`/me` matrix, role-middleware coverage once PR-S3 lands, password hash/verify) deferred to PR-S7.

### Smoke-test guidance (after PR-S2)

```bash
# Body-too-large
curl -i -X POST http://localhost:8080/v1/auth/login \
  -H 'content-type: application/json' \
  --data-binary @<(python3 -c "print('x'*5000)")     # → 413 body_too_large

# Rate limit: 10 req/min/IP
for i in $(seq 1 12); do curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://localhost:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"none@x","password":"none"}'; done
# → 401 x10 then 429

# Cookie flags on a healthy login
curl -s -i -c /tmp/c.txt -X POST http://localhost:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"tower@raumdock.org","password":"…"}' | grep -i set-cookie
# → camhub_session=…; Path=/; HttpOnly; SameSite=Lax    (no Secure in dev)
```

## What is not done (next up)

### M0.5 remainder

- **PR-S3** — Central AuthN/AuthZ middleware (SEC-003): `Principal` in context, `RequireSession`, `RequireRole`, three router groups.
- **PR-S4** — CSRF for cookie-auth mutating routes (SEC-004): double-submit token, Origin/Referer check, bypass for `Authorization: Bearer` flows.
- **PR-S5** — Session model & lifecycle (SEC-005, SEC-009): decide [Plan.md](Plan.md) §15 Q8 + Q9, remove or actually use `SessionKey`, implement refresh/rotation, background `PurgeExpired`.
- **PR-S6** — Bootstrap secret handling (SEC-007): `--password-file`, TTY prompt, README updates.
- **PR-S7** — Security regression tests (SEC-010): password hash/verify, login-cookie-flag handler tests, `/me` matrix, role-middleware tests.

### Product milestones (blocked by M0.5 PR-S1..S4 + S6)

- **M1 — Device enrollment + DNS**: `/v1/devices/register`, `/v1/devices/heartbeat`, Cloudflare DNS create/update, enrollment-token admin UI, cam list page
- **M2 — OBS URLs**: PAT minting, `/v1/obs/{cam}` redirect + signed URLs
- **M3 — Remote commands**: WSS control channel, command-signing key, audit log UI, companion changes in RDOC-RaspiCam
- **M4 — Hardening**: TOTP for admin role, hash-chained audit log, backup sidecar (login rate limiting already shipped in PR-S2)
- **M5 — Multi-camera-model polish**: capability descriptor UI, PTZ command

## How to run locally

```bash
make secrets-init           # one-time: write secrets/postgres_password, session_key, db_url
docker compose up -d --build

curl -s http://localhost:8080/healthz | jq
docker compose exec camhub /app/camhub bootstrap-admin \
  --email you@example.org --password 'change-me-please'
curl -s -c cookies.txt -X POST http://localhost:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.org","password":"change-me-please"}' | jq
curl -s -b cookies.txt http://localhost:8080/v1/auth/me | jq
```

Tear down with `docker compose down` (`-v` to wipe pgdata).
