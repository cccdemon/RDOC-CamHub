#!/bin/sh
# Entrypoint shim: caddy-dns/cloudflare reads CF_API_TOKEN from the
# environment, not from a *_FILE path. Bridge Docker secrets to env here so
# the Caddyfile {env.CF_API_TOKEN} reference resolves.
set -eu

if [ -n "${CF_API_TOKEN_FILE:-}" ] && [ -f "$CF_API_TOKEN_FILE" ]; then
    CF_API_TOKEN="$(cat "$CF_API_TOKEN_FILE")"
    export CF_API_TOKEN
fi

exec caddy "$@"
