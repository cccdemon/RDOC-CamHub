.PHONY: build test lint run stop image migrate-up migrate-down secrets-init clean

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
secrets-init:
	@mkdir -p secrets
	@test -f secrets/postgres_password || (head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'         > secrets/postgres_password && echo "wrote secrets/postgres_password")
	@test -f secrets/session_key       || (head -c 32 /dev/urandom | base64 | tr -d '\n'              > secrets/session_key       && echo "wrote secrets/session_key")
	@test -f secrets/db_url            || (printf 'postgres://camhub:%s@postgres:5432/camhub?sslmode=disable' "$$(cat secrets/postgres_password)" > secrets/db_url && echo "wrote secrets/db_url")
	@chmod 600 secrets/*

clean:
	rm -rf bin/
