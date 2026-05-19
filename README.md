# RDOC-CamHub

Central directory, auth broker, and control plane for a fleet of [RDOC-RaspiCam](../RDOC-RaspiCam/) devices.

**Not** a stream proxy. Cams continue to serve WebRTC/HLS/RTMP directly. CamHub owns identity, DNS, presence, OBS-ready URLs, and a control channel.

See [Plan.md](Plan.md) for the full design. This README only covers running the current skeleton.

## Status

**Milestone 0 — skeleton.** What works:

- `/healthz`
- Username + password login (Argon2id) → session cookie
- `camhub bootstrap-admin` CLI to seed the first admin
- Postgres migrations via goose

Everything else from [Plan.md](Plan.md) is unimplemented.

## Quick start (local dev)

```bash
# 1. Start the stack
docker compose up -d --build

# 2. Wait for the DB to be ready, then bootstrap an admin
docker compose exec camhub /app/camhub bootstrap-admin \
  --email you@example.org --password 'change-me'

# 3. Smoke test
curl -s http://localhost:8080/healthz | jq
curl -s -c cookies.txt -X POST http://localhost:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.org","password":"change-me"}'
```

## Layout

```
cmd/camhub/         # main + CLI subcommands
internal/
  config/           # env-driven config loader
  db/               # pgx pool + queries
  migrations/       # goose SQL migrations (embedded)
  auth/             # password hashing, sessions
  httpapi/          # chi router, handlers, middleware
web/templates/      # htmx-rendered UI (placeholder in M0)
deploy/             # Caddyfile, compose, Dockerfile
```

## Configuration

All config via env vars; secrets via file paths (never inline).

| Var | Default | Purpose |
|---|---|---|
| `CAMHUB_LISTEN` | `:8080` | HTTP listen address |
| `CAMHUB_DB_URL` / `CAMHUB_DB_URL_FILE` | _required_ | `postgres://user:pass@host:5432/camhub` |
| `CAMHUB_SESSION_KEY_FILE` | _required_ | ≥32-byte secret. Currently loaded but unused (see Plan §16 PR-S5) |
| `CAMHUB_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `CAMHUB_COOKIE_DOMAIN` | empty | Domain attribute on session/CSRF cookies. Leave empty for host-only cookies |
| `CAMHUB_DEV_INSECURE_COOKIE` | unset | Set to `1` for local plain-HTTP dev. Disables the `Secure` cookie attribute. **Never set in production.** |
| `CAMHUB_TRUSTED_PROXIES` | empty | Comma-separated CIDRs whose `X-Forwarded-For` / `X-Real-IP` are trusted. Empty → headers ignored, peer addr used. Example: `172.16.0.0/12,10.0.0.0/8` |
| `CAMHUB_LOGIN_RATE_PER_IP` | `10` | Login attempts allowed per window per client IP. `0` disables the limiter |
| `CAMHUB_LOGIN_RATE_WINDOW_SECS` | `60` | Rolling window for the login limiter, in seconds. `0` disables the limiter |
| `CAMHUB_ALLOWED_ORIGINS` | empty | Comma-separated full origins for the CSRF `Origin`/`Referer` allow-list, e.g. `https://app.raumdock.org,https://api.raumdock.org`. Empty disables the check (token alone gates the request). **Set in production.** |

### Trusted-proxy hint for Docker Compose

When camhub runs behind Caddy in the bundled compose stack, the immediate peer
is Caddy's container IP (typically inside `172.16.0.0/12`). Set
`CAMHUB_TRUSTED_PROXIES=172.16.0.0/12` on the `camhub` service to honor
Caddy's `X-Forwarded-For` and get real client IPs in logs, sessions, and the
login rate limiter.

## License

AGPL-3.0-or-later.
