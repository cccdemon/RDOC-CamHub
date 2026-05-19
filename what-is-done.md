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

### ✅ PR-S3 — Central AuthN/AuthZ middleware (SEC-003)

- [internal/db/sessions.go](internal/db/sessions.go) — new `SessionWithUser` struct + `GetActiveWithUser(ctx, id)`. Single JOINed query (`sessions JOIN users` with `WHERE expires_at > now()`), so expired sessions are filtered server-side and look identical to "unknown session" to the caller. One round-trip per authenticated request.
- [internal/httpapi/principal.go](internal/httpapi/principal.go) — new `Principal{UserID, Email, Role, SessionID}` type. `PrincipalFrom(ctx) (Principal, bool)` is the public read API; `withPrincipal(ctx, p)` is package-internal so handlers can't fake a principal.
- [internal/httpapi/middleware_auth.go](internal/httpapi/middleware_auth.go) — two middlewares:
  - `(*Server).RequireSession` — reads the session cookie, calls `GetActiveWithUser`, attaches the `Principal`. Missing / unknown / expired all collapse into one 401 `unauthorized` (no enumeration leak). DB error → 500.
  - `RequireRole(roles ...db.Role)` — variadic any-of. Mounted after `RequireSession`; refuses to run on its own (returns 401 if no principal in context).
- [internal/httpapi/router.go](internal/httpapi/router.go) — router restructured into three explicit chi `Group`s: **public** (`/healthz`, `/v1/auth/login`, `/v1/auth/logout`), **authenticated** (`/v1/auth/me`, mounts `RequireSession`), **admin** (declared but empty in PR-S3; future endpoints land here). Logout stays public deliberately — `SameSite=Lax` defangs cross-site forced logout, and stale-cookie holders can clear state cleanly. `SessionWriter` interface gained `GetActiveWithUser`.
- [internal/httpapi/auth.go](internal/httpapi/auth.go) — `/me` collapsed from 30 lines (cookie read + Sessions.Get + expiry check + Pool.QueryRow for role) to ~8 lines: it just reads `PrincipalFrom(ctx)`. All session/role logic lives in middleware.

### ✅ PR-S5 — Session model & lifecycle (SEC-005, SEC-009)

Resolved Plan §15 Q8 (Option A: keep random session id, drop `SessionKey`) and Q9 (Option A: 15 min access cookie + 7 d rotating refresh window). Ships rotation, hard-cap enforcement, and background purge.

- [internal/auth/session.go](internal/auth/session.go) — split the lone `SessionTTL` into `SessionAccessTTL = 15 * time.Minute` (cookie + server-side `expires_at` window) and `SessionRefreshWindow = 7 * 24 * time.Hour` (hard cap measured from `created_at`).
- [internal/db/sessions.go](internal/db/sessions.go) — new `Rotate(ctx, oldID, newID, accessTTL, refreshWindow)`. Transactional `SELECT … FOR UPDATE` on the old row, hard-cap check in Go, atomic `UPDATE` swapping `id` + `refreshed_at` + `expires_at`. Returns `ErrNotFound` for unknown-id and beyond-window — same response so callers can collapse them. `expires_at > now()` is **not** checked here on purpose: refresh is the renewal mechanism, so insisting on a still-active access window would defeat the point.
- [internal/httpapi/auth.go](internal/httpapi/auth.go) — `refresh` handler. Reads the session cookie, mints a new id, calls `Rotate`, writes new session + new CSRF cookies on success (204), clears both cookies on any failure (401). `writeRefreshFailure` helper enforces identical response shape across failure paths.
- [internal/httpapi/router.go](internal/httpapi/router.go) — `POST /v1/auth/refresh` mounted in the **public** group. Rationale documented inline: putting it behind `RequireSession` would defeat its purpose; CSRF is unnecessary because SameSite=Lax blocks cross-site cookie-bearing POSTs.
- [internal/httpapi/cookie.go](internal/httpapi/cookie.go) — both `NewSession` and `NewCSRF` now use `auth.SessionAccessTTL` for `Expires` (was the old 7 d `SessionTTL`).
- [cmd/camhub/main.go](cmd/camhub/main.go) — background goroutine: one immediate purge at startup, then every 10 min. Exits cleanly on context cancellation. Reads expired-row count only when > 0 to keep the log quiet.
- [internal/config/config.go](internal/config/config.go) — removed `SessionKey []byte` field, the `readSecret("CAMHUB_SESSION_KEY", …)` block, the `≥ 32 bytes` validation, and the unused `errors` import.
- [docker-compose.yml](docker-compose.yml) + [docker-compose.prod.yml](docker-compose.prod.yml) — dropped `CAMHUB_SESSION_KEY_FILE` from env, `session_key` from the `secrets` list, and the top-level `session_key` declaration.
- [Makefile](Makefile) — `secrets-init` no longer writes `secrets/session_key`; `secrets-check-prod` no longer verifies it.
- [.github/workflows/ci.yml](.github/workflows/ci.yml) — removed `CAMHUB_SESSION_KEY` from the test env.
- [README.md](README.md) — dropped the `CAMHUB_SESSION_KEY_FILE` row from the config table.
- Tests — [internal/httpapi/refresh_test.go](internal/httpapi/refresh_test.go) (new): no-cookie / unknown-session / beyond-window / DB-error / valid-rotation paths; `stubSessions.Rotate` mirrors the real store's invalidate-old / install-new semantics so the "old id no longer usable" check is meaningful. Plus cookie-TTL pin tests for both `NewSession` and `NewCSRF`.

### ✅ PR-S4 — CSRF for cookie-auth mutating routes (SEC-004)

Double-submit token plus an optional Origin/Referer allow-list as defense in depth. PATs (Bearer auth, M2) bypass automatically.

- [internal/auth/session.go](internal/auth/session.go) — new `NewCSRFToken()` (32-byte random hex, independent of session ID) and the constants `CSRFCookieName = "camhub_csrf"` and `CSRFHeaderName = "X-CSRF-Token"`.
- [internal/httpapi/cookie.go](internal/httpapi/cookie.go) — `SessionCookieConfig.NewCSRF(value)` (HttpOnly=false so JS can echo it back) and `NewClearingCSRF()` for logout. Same `Secure`/`Domain`/`Path`/`SameSite=Lax` as the session cookie; expiry tracks `SessionTTL`.
- [internal/httpapi/middleware_csrf.go](internal/httpapi/middleware_csrf.go) — `(*Server).RequireCSRF`. Order: safe-method skip (GET/HEAD/OPTIONS) → Bearer-auth skip → Origin/Referer allow-list (skipped if `AllowedOrigins` is empty) → cookie present → header present → constant-time compare via `crypto/subtle.ConstantTimeCompare`. Distinct error codes (`csrf_origin`, `csrf_missing`, `csrf_mismatch`) for ops debugging; all return 403.
- [internal/config/config.go](internal/config/config.go) — new `AllowedOrigins []string` field + `CAMHUB_ALLOWED_ORIGINS` (comma-separated full origins, e.g. `https://app.raumdock.org`). Helper `parseCommaList` shared with future config fields.
- [internal/httpapi/router.go](internal/httpapi/router.go) — `Options.AllowedOrigins` plumbed to `Server`. **Both** the authenticated and admin groups mount `RequireCSRF` after `RequireSession`/`RequireRole`. Pre-wired so M1's admin POSTs inherit CSRF automatically.
- [internal/httpapi/auth.go](internal/httpapi/auth.go) — login now also generates a CSRF token and writes the `camhub_csrf` cookie alongside the session cookie. Logout clears both.
- [cmd/camhub/main.go](cmd/camhub/main.go) — `allowed_origins` count is logged on startup.
- [README.md](README.md) — `CAMHUB_ALLOWED_ORIGINS` documented.

### Tests added in M0.5 so far

[internal/httpapi/](internal/httpapi/) — 32 test functions, ~17 additional subcases, all passing with `-race` (50 invocations total):

- [cookie_test.go](internal/httpapi/cookie_test.go) — cookie flag invariants (HttpOnly, SameSite=Lax, Secure follows config) in prod, prod-with-domain, dev-insecure; clearing-cookie keeps flags asserted.
- [trusted_ip_test.go](internal/httpapi/trusted_ip_test.go) — XFF / RealIP trust matrix: empty list ignores XFF, untrusted peer ignores XFF, trusted peer uses XFF, chain-walking stops at first untrusted hop, all-trusted chain returns innermost proxy, X-Real-IP fallback, malformed XFF safety, IPv6 peer.
- [rate_limit_test.go](internal/httpapi/rate_limit_test.go) — nil-when-disabled, budget exhaustion → 429, per-IP isolation, refill over window.
- [auth_test.go](internal/httpapi/auth_test.go) — handler-level login tests: 413 body-too-large before DB; 400 length-cap before Argon2id (timing-asserted); 400 email-too-long before DB; byte-identical error parity for unknown-email vs wrong-password.
- [middleware_auth_test.go](internal/httpapi/middleware_auth_test.go) — `RequireSession`: no cookie → 401, unknown session → 401, expired-as-missing parity, DB error → 500, valid → 200 + correct `Principal` in context. `RequireRole`: no principal upstream → 401, wrong role → 403, any-of matching admin/operator/viewer. `/me`: returns user info from principal, 401 if principal missing.
- [middleware_csrf_test.go](internal/httpapi/middleware_csrf_test.go) — `RequireCSRF`: safe methods (GET/HEAD/OPTIONS) bypass; Bearer-auth bypasses; missing cookie → 403; missing header → 403; cookie/header mismatch → 403; valid match → through. Origin allow-list: empty list disables the check; matching `Origin` passes; mismatched origin blocks; Referer fallback works; no Origin/Referer with non-empty list blocks. `Login`: writes both `camhub_session` (HttpOnly) and `camhub_csrf` (NOT HttpOnly) cookies on success.

Remaining auth tests (password hash/verify direct, full HTTP integration with real cookies through chi) deferred to PR-S7.

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

## Production deployment scaffolding (2026-05-19)

Repo-side artifacts to deploy CamHub into the public services LXC (`10.10.10.99`, same host as RDOC-WEBRTC) behind LXC 101's nginx SNI router. **Not yet applied** — user runs the deploy.

- [docker-compose.prod.yml](docker-compose.prod.yml) — compose override. Caddy binds `:8443` only (RDOC-WEBRTC's Caddy keeps `:443`). `CAMHUB_COOKIE_DOMAIN=camhub.raumdock.org`, `CAMHUB_ALLOWED_ORIGINS=https://app.camhub.raumdock.org`, dev-insecure-cookie escape hatch removed, Cloudflare API token mounted as Docker secret.
- [deploy/Caddyfile.prod](deploy/Caddyfile.prod) — rewritten for `app.camhub.raumdock.org:8443` + `api.camhub.raumdock.org:8443`. `acme_dns cloudflare {env.CF_API_TOKEN}`, `auto_https disable_redirects` (no `:80`). Common headers (HSTS, nosniff, Referrer-Policy, CSP placeholder).
- [deploy/caddy/Dockerfile](deploy/caddy/Dockerfile) — `caddy:builder` + `xcaddy build --with github.com/caddy-dns/cloudflare`, mirrors RDOC-WEBRTC's pattern.
- [deploy/caddy/entrypoint.sh](deploy/caddy/entrypoint.sh) — bridges `CF_API_TOKEN_FILE` Docker secret → `CF_API_TOKEN` env var (caddy-dns/cloudflare doesn't read `*_FILE` itself).
- [deploy/lxc101-nginx-camhub.conf](deploy/lxc101-nginx-camhub.conf) — patch instructions for `/etc/nginx/stream.d/minecraft.raumdock.org.conf` on LXC 101: two map entries + `upstream camhub_lxc { server 10.10.10.99:8443; }`. SNI-only, no TLS termination on the edge.
- [Makefile](Makefile) — new `prod-up`, `prod-down`, `prod-build`, `prod-logs`, `secrets-check-prod` targets. `secrets-check-prod` refuses to bring up the stack until `secrets/cf_api_token` exists.
- [README.md](README.md) — "Production deploy" section with one-time setup and smoke tests.
- [Plan.md](Plan.md) §12 — rewritten to reflect the actual topology (LXC 101 SNI → public LXC `:8443` → CamHub Caddy → camhub:8080) instead of the original "single host with Caddy on 80/443" sketch.

Open before applying:
- Cloudflare API token (Zone:DNS:Edit on `raumdock.org`) needs to land in `secrets/cf_api_token` on the public LXC.
- LXC 101 nginx patch + `systemctl reload nginx`.
- Verify nothing else on `10.10.10.99` already binds `:8443`.

## What is not done (next up)

### M0.5 remainder

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
make secrets-init           # one-time: write secrets/postgres_password, db_url
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
