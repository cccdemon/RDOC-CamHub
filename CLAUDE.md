# CLAUDE.md

Working agreements for Claude sessions in this repo. Read this before doing anything beyond reading files.

## The three keys

1. **Plan mode first. Check your plan twice.**
   Enter plan mode for any non-trivial change. Before calling `ExitPlanMode`, re-read the plan from top to bottom and confirm: scope matches the request, file paths are real, no step assumes something you haven't verified.

2. **Before you edit, review your idea.**
   Re-read the target file(s) and the relevant plan section immediately before issuing `Edit` or `Write`. Confirm the change still matches the plan in light of what's actually in the file.

3. **Explain your steps, short form.**
   One sentence before a meaningful tool call. End-of-turn summary: at most two sentences.

## Project shape

CamHub is the hub-side of the RDOC fleet. **Not a stream proxy** — see [Plan.md](Plan.md) §2. The cam-side contract is documented in [../RDOC-RaspiCam/Architecture.md](../RDOC-RaspiCam/Architecture.md) §"CamHub integration". Changes to API endpoints under `/v1/devices/*` are coordinated changes with that repo.

Stack: Go 1.23 + Postgres + chi + pgx + goose + htmx + Caddy. Single static binary in a `scratch` image.

## What typically changes here

- `internal/httpapi/` — handlers + middleware.
- `internal/db/` + `internal/migrations/` — schema and queries.
- `internal/auth/` — password hashing, sessions, JWT (device side, future).
- `cmd/camhub/` — entrypoint and CLI subcommands.
- `deploy/` — Dockerfile, Compose, Caddyfile.

## Don'ts

- Don't put secrets in env vars — read them from file paths. Compose mounts via Docker secrets.
- Don't commit `secrets/`, `data/`, or `.env*`.
- Don't proxy video traffic through the hub. The hub redirects; cams serve.
- Don't add a `shell_exec` command to the remote-command channel (Plan §7.3).
- Don't bake Cloudflare tokens into the image.
- Don't bypass git hooks (`--no-verify`, `--no-gpg-sign`).
- Don't `git add -A` blindly — stage specific files.

## Build / verify

```
make build         # go build → ./bin/camhub
make test          # go test ./...
make lint          # go vet + staticcheck
make migrate-up    # apply migrations against $CAMHUB_DB_URL
make image         # build the Docker image
make run           # docker compose up -d --build
```

## Where to look first

| Question | File |
|---|---|
| What is this project? | [README.md](README.md), [Plan.md](Plan.md) |
| HTTP entrypoint? | [cmd/camhub/main.go](cmd/camhub/main.go) |
| Routes? | [internal/httpapi/router.go](internal/httpapi/router.go) |
| Schema? | [internal/migrations/](internal/migrations/) |
| Auth? | [internal/auth/](internal/auth/) |
