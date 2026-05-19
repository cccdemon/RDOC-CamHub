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
| `CAMHUB_DB_URL` | _required_ | `postgres://user:pass@host:5432/camhub` |
| `CAMHUB_SESSION_KEY_FILE` | `/run/secrets/session_key` | 32-byte key for signing session cookies |
| `CAMHUB_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |

## License

AGPL-3.0-or-later.
