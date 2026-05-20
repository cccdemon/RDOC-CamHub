.PHONY: build test lint run stop image migrate-up migrate-down secrets-init clean \
        prod-up prod-down prod-build prod-logs secrets-check-prod

GO := go
BIN := bin/camhub
PKG := ./...

build:
	$(GO) build -trimpath -o $(BIN) ./cmd/camhub

test:
	$(GO) test -race -count=1 $(PKG)

lint:
	$(GO) vet $(PKG)
	@command -v staticcheck >/dev/null 2>&1 && staticcheck $(PKG) || echo "staticcheck not installed; skipping"

run:
	docker compose up -d --build

stop:
	docker compose down

image:
	docker compose build camhub

migrate-up:
	$(GO) run ./cmd/camhub migrate up

migrate-down:
	$(GO) run ./cmd/camhub migrate down

# One-time: generate local-dev secrets.
# Passwords are hex (URL-safe, no escaping needed in the DSN).
# Session key is base64 (only the byte length matters; the file contents are the key).
#
# Ownership: camhub runs as uid 65532 inside its container (USER directive
# in deploy/Dockerfile). Docker Compose's file-based secrets honor neither
# uid/gid/mode options outside Swarm, so the host file's owner must match
# what the container's process expects. We chown db_url to 65532.
# postgres_password stays root-owned — postgres-alpine reads it as root
# before dropping privs.
secrets-init:
	@mkdir -p secrets
	@test -f secrets/postgres_password || (head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'         > secrets/postgres_password && echo "wrote secrets/postgres_password")
	@test -f secrets/db_url            || (printf 'postgres://camhub:%s@postgres:5432/camhub?sslmode=disable' "$$(cat secrets/postgres_password)" > secrets/db_url && echo "wrote secrets/db_url")
	@# Device-JWT signing ring (M1.B). Generated via the camhub binary
	@# because ed25519 keypair generation isn't a clean bash one-liner.
	@test -f secrets/device_jwt_ring.json || ($(GO) run ./cmd/camhub devicejwt init --out secrets/device_jwt_ring.json && echo "wrote secrets/device_jwt_ring.json")
	@chmod 600 secrets/*
	@chown 65532:65532 secrets/db_url secrets/device_jwt_ring.json 2>/dev/null && echo "chowned db_url + device_jwt_ring.json to 65532:65532 (camhub uid)" || \
	    echo "WARN: chown to 65532 failed — run 'sudo chown 65532:65532 secrets/db_url secrets/device_jwt_ring.json' or expect EACCES inside the camhub container"

clean:
	rm -rf bin/

# ----- Production (public LXC, sibling to RDOC-WEBRTC) --------------------
# Compose base + prod override. See docker-compose.prod.yml and
# deploy/lxc101-nginx-camhub.conf.

COMPOSE_PROD := docker compose -f docker-compose.yml -f docker-compose.prod.yml

prod-up: secrets-check-prod
	$(COMPOSE_PROD) up -d --build

prod-down:
	$(COMPOSE_PROD) down

prod-build:
	$(COMPOSE_PROD) build

prod-logs:
	$(COMPOSE_PROD) logs -f --tail=200

# Prod needs a Cloudflare API token in addition to the dev secrets. We never
# generate this — it's a real credential. Just verify it exists.
secrets-check-prod:
	@test -f secrets/postgres_password    || (echo "missing secrets/postgres_password — run 'make secrets-init'" && exit 1)
	@test -f secrets/db_url               || (echo "missing secrets/db_url — run 'make secrets-init'" && exit 1)
	@test -f secrets/device_jwt_ring.json || (echo "missing secrets/device_jwt_ring.json — run 'make secrets-init'" && exit 1)
	@test -f secrets/cf_api_token         || (echo "missing secrets/cf_api_token — write your Cloudflare API token (Zone:DNS:Edit on raumdock.org) into this file, then chmod 600" && exit 1)
	@# camhub runs as uid 65532; the secrets it reads must be owned by that uid.
	@stat -c '%u' secrets/db_url               | grep -q '^65532$$' || (echo "secrets/db_url not owned by uid 65532 — running: chown 65532:65532 secrets/db_url" && chown 65532:65532 secrets/db_url)
	@stat -c '%u' secrets/device_jwt_ring.json | grep -q '^65532$$' || (echo "secrets/device_jwt_ring.json not owned by uid 65532 — running: chown" && chown 65532:65532 secrets/device_jwt_ring.json)
	@stat -c '%u' secrets/cf_api_token         | grep -q '^65532$$' || (echo "secrets/cf_api_token not owned by uid 65532 — running: chown" && chown 65532:65532 secrets/cf_api_token)
	@chmod 600 secrets/db_url secrets/device_jwt_ring.json secrets/cf_api_token
	@echo "prod secrets present"
