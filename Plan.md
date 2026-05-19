# RDOC-CamHub — Implementation Plan

Central directory, auth broker, and control plane for a fleet of RDOC-RaspiCam devices.
**Not** a stream proxy — cams continue to serve WebRTC/HLS/RTMP directly. CamHub only owns identity, DNS, presence, OBS-ready URLs, and a control channel.

The contract on the cam side is already partly defined in [RDOC-RaspiCam/Architecture.md](../RDOC-RaspiCam/Architecture.md) (§ "CamHub integration") and in `camhub-register.sh`. This plan is the hub-side counterpart.

---

## 1. Goals

- Each RaspiCam auto-registers with CamHub on boot and receives a stable public DNS name (`<name>.raumdock.org`).
- A single web UI lists all cams with state (online/offline, last seen, public IP, stream URLs).
- Provide ready-to-paste **OBS Browser-Source URLs** per cam, authenticated by an API token bound to the OBS user.
- Provide a **remote-command channel** to each cam (restart stream, reboot, change bitrate, toggle audio, pull update, run pre-approved actions).
- Support cams beyond the Logitech C920 — anything the cam-side V4L2 pipeline can encode is accepted; CamHub treats cams as opaque stream endpoints with a capability descriptor.
- Strong authentication and end-to-end TLS on every hop.

## 2. Non-goals (explicit)

- **No stream proxying.** CamHub never sits in the video path. Browser clients hit the cam's public hostname directly. This keeps bandwidth off the hub and avoids re-encode latency.
- No multi-tenant isolation in v1. Single org (Raumdock). Per-user roles, but one tenant.
- No mobile app. Web UI only.
- No recording/DVR. That's an OBS concern.

## 3. DNS strategy

The convention has shifted from the original `cam1.camhub.raumdock.org` to **flat `<name>.raumdock.org`** (e.g. `cam1.raumdock.org` already exists, plus `livingroom`, `bedroom`, `mobile1`, …).

- CamHub owns the Cloudflare API token with `Zone.DNS:Edit` on `raumdock.org`.
- On device registration, the hub:
  1. Picks the requested `CAM_NAME` if free, else appends `-2`, `-3`, … (configurable: numeric vs. dash-suffix).
  2. Creates an `A` (and `AAAA` where IPv6 was provided) record `<name>.raumdock.org` → cam's reported public IP.
  3. Returns `assigned_subdomain` to the cam.
- On heartbeat, the hub updates the A/AAAA records when the cam's public IP changes.
- TTL low (60 s) on these records to keep IP changes responsive.
- A **reserved-name list** prevents cams from claiming `api`, `app`, `hub`, `admin`, `www`, `mail`, etc.

> Note: existing entries (`cam1.raumdock.org`) must be imported into CamHub's DB on first run, not duplicated. Provide a `camhub-cli import-dns` command.

## 4. Device authentication (cam → hub)

Two-stage, as already prototyped in `camhub-register.sh`.

### 4.1 Enrollment (one-time, short-lived token)

- Admin generates an enrollment token in the CamHub UI (or CLI): random 32-byte URL-safe string, single-use, TTL 24 h.
- Token is written into the cam's `/opt/server-tech/.env` as `CAMHUB_TOKEN` (per existing convention — see [RDOC-RaspiCam/CLAUDE.md](../RDOC-RaspiCam/CLAUDE.md) "Don'ts": must not be baked into the image).
- Cam POSTs `/v1/devices/register` with `{device_id, preferred_name, public_ip, public_ipv6?, ports, capabilities}` + `Authorization: Bearer <enrollment_token>`.
- Hub validates the token, assigns subdomain, creates DNS records, issues a long-lived **device JWT** (signed by hub, includes `device_id`, `assigned_subdomain`, `iat`, `kid`). No `exp` — rotation via `kid` instead.
- Hub returns `{assigned_subdomain, device_jwt, hub_cert_fingerprint}`. Cam pins the fingerprint (TOFU) into `.camhub-cert.pem`.
- Enrollment token is burned (one-shot) regardless of outcome on the hub side. Failure → admin generates a new one.

### 4.2 Heartbeat & ongoing auth

- Cam calls `/v1/devices/heartbeat` every 5 min (existing timer) with `Authorization: Bearer <device_jwt>`.
- Body: `{public_ip, public_ipv6?, status, stream_health, version}`.
- Hub updates `last_seen`, refreshes DNS if IP changed.
- A cam silent for > 15 min is marked **offline** in the UI; DNS records are kept (so deep links remain stable) but flagged.

### 4.3 Device JWT key rotation

- Hub signs JWTs with an Ed25519 keypair stored in `secrets/jwt-signing.key` (managed by Docker secrets, not env).
- Multiple `kid`s supported for rolling rotation. Old `kid` accepted for 30 days after retirement, then refused — cams must re-enroll.

### 4.4 Capabilities descriptor

Replaces the C920 assumption. Cam sends on register & heartbeat:

```json
{
  "model": "Logitech HD Pro Webcam C920",
  "v4l2_device": "/dev/video0",
  "native_h264": true,
  "max_resolution": "1920x1080",
  "max_fps": 30,
  "audio": true,
  "controls": ["pan", "tilt", "zoom"],
  "encoder": "v4l2m2m"
}
```

The hub stores this verbatim and exposes it in the UI. Cams beyond C920 (USB UVC, CSI cameras, IP cams remuxed locally) just send their own descriptor — no hub-side allow-list.

## 5. User / OBS authentication (clients → hub & UI)

Two flows, both end-to-end TLS:

### 5.1 Web UI (humans)

- Username + password, Argon2id-hashed at rest.
- Session via short-lived (15 min) signed cookie + refresh token (7 days, rotating).
- TOTP 2FA optional but **required for admin role** in v1.
- Roles: `admin` (manage users, cams, DNS, enrollment), `operator` (view + issue allowed commands), `viewer` (read-only + OBS URL access).

### 5.2 OBS / programmatic (API tokens)

- A user can mint **API tokens** from the UI, scoped to:
  - One or more cams (`cam_ids: ["livingroom", "bedroom"]` or `*`)
  - One or more capabilities (`stream:view`, `cam:command:restart`, `cam:command:*`)
- Token format: `rdoc_pat_` + 40 random URL-safe chars. Stored as Argon2id hash on the hub.
- Used as `Authorization: Bearer <token>` for the API, **or** appended to OBS Browser-Source URLs as a single-use signed query param (see § 6).

## 6. OBS Browser-Source URLs

The point of the hub here is to give OBS a single URL that:
- Is stable per cam.
- Embeds auth so OBS doesn't have to prompt.
- Redirects to the cam's actual WebRTC/HLS endpoint.

### Design

`https://api.raumdock.org/v1/obs/<cam>?token=<api_token>&protocol=webrtc`

- Hub authenticates the token, checks scope, then **302-redirects** to the cam's direct URL: `https://livingroom.raumdock.org/whep` (WebRTC) or `/hls/stream.m3u8`.
- For protocols where redirect doesn't work cleanly (HLS playlists rewriting segment URLs), provide a small JS shim served from `api.raumdock.org/v1/obs/embed/<cam>` that loads the player against the cam's hostname directly. The shim itself is hub-served; the *media* still flows cam → browser.
- Optional: hub can mint **short-lived (1 h) signed URLs** to be embedded in OBS without exposing the long-lived PAT. UI button: "Copy OBS URL (signed)".

### Quality-of-life

- "Copy OBS URL" buttons in the UI for each protocol.
- "Test in browser" link that opens the same URL in a new tab.
- Per-cam status badge: green when last heartbeat < 5 min and the hub's recent `HEAD` probe of the cam's `/healthz` returned 200.

## 7. Remote-command channel

This is the trickiest piece because it requires the hub to *talk to* cams behind NAT.

### 7.1 Transport: WebSocket persistent connection (cam → hub)

- Each cam opens an outbound WSS to `wss://api.raumdock.org/v1/devices/control` with its device JWT.
- Hub holds the socket; commands are pushed cam-ward over this connection.
- Heartbeat ping/pong every 30 s; auto-reconnect with exp. backoff.
- Outbound-only from cam → no router/firewall changes needed. Works behind CGNAT.

### 7.2 Command schema

```json
{
  "id": "01HX...ULID",
  "cmd": "restart_stream" | "reboot" | "set_bitrate" | "set_audio" | "git_pull" | "shell_exec",
  "args": { ... },
  "issued_by": "user_id",
  "issued_at": "2026-05-19T12:34:56Z",
  "expires_at": "2026-05-19T12:35:56Z",
  "signature": "ed25519(payload, hub_signing_key)"
}
```

- The cam verifies the hub's signature using the pinned `hub_cert_fingerprint` (or a separate command-signing pubkey shipped at enrollment — cleaner). This prevents a compromised TLS endpoint from issuing commands.
- Cam responds with `{id, status: "ok"|"error", output, completed_at}`.

### 7.3 Command catalog (initial)

| Command | Effect on cam |
|---|---|
| `restart_stream` | `systemctl restart chaoscrew-streaming` |
| `reboot` | `systemctl reboot` (10 s grace) |
| `set_bitrate` | Patch `.env`, restart stream |
| `set_audio` | Toggle `AUDIO_ENABLED`, restart stream |
| `git_pull` | `cd /opt/server-tech && git pull && systemctl restart …` |
| `set_video_mode` | Switch between `auto` / `camera_h264` / `mjpeg_h264_v4l2m2m` / `mjpeg_libx264` |
| `get_logs` | Tail `journalctl -u chaoscrew-streaming -n 200` and return |
| `ptz` | For controls-capable cams, issue UVC pan/tilt/zoom |

**No generic `shell_exec` in v1.** Allow-list of explicit commands only. Adding a new command requires both a hub-side and cam-side change — by design.

### 7.4 Audit log

Every command issued is persisted: who, when, to which cam, exit status, output. Visible to admins; immutable from the UI.

## 8. API surface (v1)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/devices/register` | enrollment token | Initial enrollment |
| `POST` | `/v1/devices/heartbeat` | device JWT | Periodic check-in, IP refresh |
| `GET`  | `/v1/devices` | session/PAT (`viewer+`) | List cams |
| `GET`  | `/v1/devices/{id}` | session/PAT | One cam + capabilities + status |
| `POST` | `/v1/devices/{id}/commands` | session/PAT (`operator+` + scope) | Issue a command |
| `GET`  | `/v1/devices/{id}/commands` | session/PAT | Command history for this cam |
| `GET`  | `/v1/obs/{cam}` | PAT query-param | 302 → cam's stream URL |
| `WS`   | `/v1/devices/control` | device JWT | Long-lived control socket (cam → hub) |
| `POST` | `/v1/auth/login` | username+password (+TOTP) | Web UI login |
| `POST` | `/v1/auth/tokens` | session (`admin` or self) | Mint API token |
| `POST` | `/v1/admin/enrollment-tokens` | session (`admin`) | Generate enrollment token |

OpenAPI spec lives at `api/openapi.yaml`, generated handlers + types.

## 9. Data model (sketch)

```
users(id, email, password_hash, totp_secret?, role, created_at)
api_tokens(id, user_id, hash, scopes, created_at, last_used_at, revoked_at?)
enrollment_tokens(id, hash, created_by, expires_at, consumed_at?, consumed_by_device_id?)
devices(id, name, subdomain, device_jwt_kid, capabilities_json,
        public_ip, public_ipv6, last_seen_at, status, enrolled_at)
dns_records(id, device_id, fqdn, type, value, cloudflare_id, updated_at)
commands(id, device_id, issued_by_user, cmd, args_json, status,
         output, issued_at, completed_at, signature)
audit_log(id, actor, action, target, payload_json, ts)
```

Postgres is overkill but fine; SQLite is enough for v1 and lets the hub run as a single container with a mounted volume. Decision deferred — see open questions.

## 10. Security posture

> The post-M0 review surfaced 10 findings ([Securityfindings.md](Securityfindings.md)) that must be addressed in **M0.5** before product endpoints expand. The bullets below are the steady-state target; see §16 for the concrete work to get there.

- **TLS everywhere.** Hub serves only HTTPS, HSTS preload. The control WS is `wss://`. Cert via Caddy + Cloudflare DNS-01 (mirrors the cam pattern).
- **Hub cert pinning** on cam side (TOFU into `.camhub-cert.pem`) — already in the cam scaffolding.
- **Hub → cam command signing** with a dedicated Ed25519 key, separate from TLS. Cam refuses unsigned commands even if WSS endpoint is reached.
- **Argon2id** for password and PAT hashing (memory cost ≥ 64 MB).
- **CSRF protection** on the web UI (SameSite=Lax cookies + double-submit token for state-changing forms).
- **Rate limiting** on `/v1/auth/login`, `/v1/devices/register`, `/v1/obs/*`.
- **No secrets in env or compose** for the hub itself — use Docker secrets / mounted files. Cloudflare token, JWT signing key, command signing key all live in `secrets/`.
- **Audit log is append-only**; nightly hash-chain checkpoint to make tampering detectable.
- **Reserved subdomain list** (see § 3) to prevent a malicious enrollment claiming `api.raumdock.org`.
- Cam-side: enrollment token is **one-shot, short-lived, transport via SSH only** — never email/Slack.

## 11. Tech stack (proposal)

- **Language**: Go. Single static binary, ergonomic for WS + HTTP + crypto, mirrors the operational simplicity of the cam stack.
- **HTTP**: `chi` router + standard `net/http`.
- **WS**: `nhooyr.io/websocket`.
- **DB**: Postgres 16 (driver `pgx/v5`, migrations via `pressly/goose`). Decided 2026-05-19 — chosen over SQLite to keep multi-instance and richer auditing options open from day 1.
- **Web UI**: Server-rendered HTML (templ + htmx) for v1. SPA only if the UX outgrows it.
- **Auth lib**: `github.com/golang-jwt/jwt/v5` + `argon2` from `golang.org/x/crypto`.
- **Cloudflare client**: `github.com/cloudflare/cloudflare-go`.
- **Container**: Single Dockerfile, multi-stage, `FROM scratch` final image. Compose file with named volumes for `data/` and `secrets/`.
- **Reverse proxy**: Caddy in front (same image pattern as `RDOC-RaspiCam/tools/caddy-cloudflare.Dockerfile`), terminating TLS for `api.raumdock.org` and `app.raumdock.org` (UI).

Rejecting alternatives explicitly:
- *Python/FastAPI*: fine, but the cam fleet is already Bash+Go-flavored systemd glue; one language across the stack reduces cognitive load.
- *Node*: same.
- *Rust*: overkill for this size; we want quick iteration first.

## 12. Deployment

Single host (Hetzner CX22 or similar) running:

```
api.raumdock.org  →  Caddy  →  camhub (8080)
app.raumdock.org  →  Caddy  →  camhub (8080, /ui/*)
```

- Compose stack: `caddy`, `camhub`, optional `backup` sidecar.
- Backups: nightly `sqlite3 .backup` → off-host (Hetzner Storage Box or S3).
- Monitoring: a `/healthz` endpoint, a `/metrics` Prometheus endpoint (admin-token gated). UptimeKuma or Healthchecks.io ping every 1 min.
- Logs: stdout → Caddy/Docker → host journal. No log shipping in v1.

## 13. Roadmap

**Milestone 0 — Skeleton (1 sprint) — ✅ Done 2026-05-19**
- Repo scaffold, Dockerfile, Compose, Caddyfile.
- `/healthz`, `/v1/auth/login`, `/v1/auth/logout`, `/v1/auth/me`, user table, password login (no TOTP yet).
- Postgres migrations via goose.

**Milestone 0.5 — Security baseline (gates M1)** — see [Securityfindings.md](Securityfindings.md) and §16 below.
- Resolve SEC-001 through SEC-010 in the priority order documented there.
- No new product endpoints (devices, OBS, commands) land until SEC-001..SEC-004 + SEC-006 are closed.
- `go test ./...` must include real auth-flow assertions before this milestone closes.

**Milestone 1 — Device enrollment + DNS (1 sprint)**
- `/v1/devices/register` and `/v1/devices/heartbeat` matching the cam-side contract.
- Cloudflare DNS create/update.
- Enrollment-token UI page (admin only).
- UI: cam list with status.

**Milestone 2 — OBS URLs (½ sprint)**
- PAT minting UI.
- `/v1/obs/{cam}` with redirect + signed-URL variant.
- "Copy OBS URL" buttons.

**Milestone 3 — Remote commands (1 sprint)**
- WS control channel + command-signing key.
- Cam-side WS client (this is a parallel change in [RDOC-RaspiCam](../RDOC-RaspiCam/)).
- Command catalog: `restart_stream`, `set_bitrate`, `set_audio`, `git_pull`, `get_logs`.
- Audit log UI.

**Milestone 4 — Hardening (½ sprint)**
- TOTP for admin role.
- Rate limiting.
- Hash-chained audit log.
- Backup sidecar.

**Milestone 5 — Multi-camera-model support polish (½ sprint)**
- Capability-descriptor UI surface.
- `ptz` command for cams that advertise the capability.
- Documented procedure for adding a new cam model to RaspiCam (mostly cam-side, but hub-side validation needs awareness).

## 14. Cam-side changes required (companion PRs in RDOC-RaspiCam)

For traceability — these are out of scope for this repo but blocking:

- `camhub-register.sh` already mostly matches § 4.1. Audit for the `hub_cert_fingerprint` response field handling.
- New: WSS client (`camhub-control.service`) that opens & maintains the control socket and dispatches commands from § 7.3.
- New: Hub command-signing pubkey distribution (during enrollment) and signature verification.
- `env.template`: keep `CAMHUB_TOKEN` empty by default (already enforced — see [RDOC-RaspiCam/CLAUDE.md](../RDOC-RaspiCam/CLAUDE.md) Don'ts).
- Capabilities descriptor: cam needs to detect & report (mostly already done in `start-streaming.sh prepare`, just needs to be POSTed).

## 15. Open questions

1. **DNS naming under conflict.** When `livingroom` is taken, do we suffix `-2` or refuse and let the admin rename? *Recommendation: suffix.*
2. ~~**SQLite vs. Postgres for v1.**~~ **Resolved 2026-05-19**: Postgres from day 1.
3. **Hub-issued TLS for cams?** Hub could mint per-cam Let's Encrypt certs and push them, instead of each cam holding a Cloudflare API token. Cleaner blast radius, more moving parts. *Recommendation: defer to v2.*
4. **Embedded recorder?** Out of scope per § 2, but worth confirming with users — some may expect "DVR-lite".
5. **Stream health probe** — should the hub HEAD `/healthz` on each cam's public hostname, or rely purely on heartbeat? *Recommendation: both, the HEAD catches "cam process up but stream broken".*
6. **OBS signed-URL TTL.** 1 h is convenient; 10 min is safer. *Recommendation: 1 h with per-token override.*
7. Should `shell_exec` ever be added (admin-only, signed twice)? *Recommendation: no, unless a concrete need appears.*
8. ~~**Session model — random ID vs HMAC-signed cookie (SEC-005).**~~ **Resolved 2026-05-20: Option A.** Random 32-byte session ID validated against the DB stays the model; `CAMHUB_SESSION_KEY` will be removed from required config in PR-S5. Revocation stays a single `DELETE FROM sessions`.
9. ~~**Session TTL — 7 d vs Plan §5.1's 15 min + refresh (SEC-009).**~~ **Resolved 2026-05-20: Option A.** 15 min access cookie + 7 d rotating refresh window. PR-S5 adds `POST /v1/auth/refresh`; refresh mints a new session id and invalidates the old one. Background goroutine in `cmd/camhub serve` purges expired sessions every 10 min.

## 16. Security baseline (M0.5) — PR-sized work

Each item below is a self-contained PR. The grouping respects the priority order from [Securityfindings.md](Securityfindings.md). PRs land in numerical order; SEC-IDs in parentheses are the source findings.

### PR-S1 — Cookie security & proxy trust (SEC-001, SEC-006, SEC-008)

- Add `CookieSecure bool` (default `true`) and `CookieDomain string` to [internal/config/config.go](internal/config/config.go); accept an explicit `CAMHUB_DEV_INSECURE_COOKIE=1` to opt out for local plain-HTTP dev.
- Plumb a small `httpapi.SessionCookieConfig` into `httpapi.Server`. Replace both `Secure: r.TLS != nil` occurrences in [internal/httpapi/auth.go](internal/httpapi/auth.go) with this config.
- Wrap `middleware.RealIP` so it only trusts `X-Forwarded-For` / `X-Real-IP` from a configurable trusted-proxy CIDR list (default: empty → header ignored). Use the resolved IP in `sessions.Create` and in the rate limiter from PR-S2.
- Split Caddy config: keep [deploy/Caddyfile](deploy/Caddyfile) as the local-dev `:80` proxy, add `deploy/Caddyfile.prod` (or a compose-override) with `api.raumdock.org` + `app.raumdock.org`, `header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`, `header X-Content-Type-Options nosniff`, `header Referrer-Policy strict-origin-when-cross-origin`, placeholder CSP for later UI work.
- Tests: handler tests asserting cookie flags (`HttpOnly`, `Secure`, `SameSite=Lax`) under prod config; proxy-trust unit tests for trusted vs untrusted source IPs.

### PR-S2 — Login hardening (SEC-002)

- Wrap login body in `http.MaxBytesReader` (4 KiB).
- Pre-Argon2 validation: email ≤ 320 chars, password ≤ 1024 chars. Return `400 bad_request` before any expensive verify.
- Per-IP rate limit on `POST /v1/auth/login` (token-bucket, e.g. 10 req / minute / IP; configurable). Optional per-normalized-email layer to slow targeted guessing without leaking enumerability.
- Use the trusted-IP function from PR-S1 — never raw `RemoteAddr`.
- Tests: oversized body → 413, oversized password → 400 *before* Argon2 latency, burst on same IP → 429, error messages remain identical for unknown-email and wrong-password.

### PR-S3 — Central AuthN/AuthZ middleware (SEC-003)

- New `internal/httpapi/principal.go` with `Principal{UserID, Email, Role, SessionID}` and a context helper.
- `RequireSession` middleware: reads cookie, loads session, attaches principal, rejects on expired/missing.
- `RequireRole(role db.Role)` middleware composes on top.
- Refactor router into three explicit groups: `r.Group(public)`, `r.Group(authenticated)` (mounts `RequireSession`), `r.Group(admin)` (mounts `RequireRole(RoleAdmin)`). Move `/v1/auth/me` into `authenticated`; it reads the principal from context.
- Tests: cover unauthenticated → 401, viewer hitting admin route → 403, valid session → 200.

### PR-S4 — CSRF protection for cookie-auth mutating routes (SEC-004)

- Pick double-submit token: server sets a random `camhub_csrf` cookie (`SameSite=Lax`, not `HttpOnly`) at session creation; mutating handlers (`POST`/`PUT`/`PATCH`/`DELETE`) require a matching `X-CSRF-Token` header.
- Middleware skips CSRF when the request authenticates via `Authorization: Bearer …` (PAT path — added in M2).
- Add `Origin`/`Referer` allow-list check as defense in depth.
- Apply automatically to the `authenticated` and `admin` router groups from PR-S3.
- Tests: missing token → 403, mismatched token → 403, valid token → 200, bearer-auth path unaffected.

### PR-S5 — Session model & lifecycle (SEC-005, SEC-009)

- Resolve open question #8 above. Default plan: keep random ID, **remove `SessionKey`** from required config, update [README.md](README.md) wording, and document the model in a new `docs/sessions.md` (or inline in CLAUDE.md).
- Resolve open question #9. Default plan: 15 min access TTL on the cookie, 7 d refresh window via `sessions.refreshed_at`; rotate `id` on each refresh. Provide `POST /v1/auth/refresh`.
- Background goroutine in `cmd/camhub serve` invokes `sessions.PurgeExpired` every 10 min.
- Tests: refresh path issues a new id and invalidates the old one; expired sessions are gone after purge; cookie TTL matches code constant.

### PR-S6 — Bootstrap secret handling (SEC-007)

- Add `--password-file` to `bootstrap-admin`; if neither flag is set and stdin is a TTY, prompt with no-echo.
- Print a stderr warning when `--password` is used and suggest the file/TTY path.
- Update [README.md](README.md) to lead with `--password-file` and remove the inline literal password.
- Keep the 12-char minimum.

### PR-S7 — Security regression tests (SEC-010)

- Backfill anything the prior PRs left out: `password_test.go` (hash/verify/wrong-password/invalid-hash), `auth_handler_test.go` (login cookie flags, logout clears cookie, `/me` no-cookie / invalid / valid), router-group tests for unauthenticated access to `authenticated`/`admin` groups.
- Once landed, M0.5 closes only when `go test -race ./...` passes and covers these invariants.

### Cross-cutting non-goals during M0.5

- No new product endpoints (devices, OBS, commands). Anything from M1+ waits.
- No big refactors outside `internal/{httpapi,config,auth}`, `cmd/camhub`, and `deploy/`.
- No secrets moved back into inline env or README examples — Docker secrets stay the canonical path.
- Run `go test ./...` after each PR.

---

*This plan is a starting point. Each milestone should land as a separate, reviewable PR; the API contract in § 8 is the public surface and changes to it after Milestone 1 require coordinated cam-side updates.*
