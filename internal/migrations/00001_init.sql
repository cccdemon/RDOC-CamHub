-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT,
    role            TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,            -- random 32-byte hex
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    refreshed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent      TEXT,
    ip              INET
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE api_tokens (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    hash            TEXT NOT NULL,               -- argon2id of the raw token
    scopes          JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);

CREATE TABLE enrollment_tokens (
    id                      BIGSERIAL PRIMARY KEY,
    hash                    TEXT NOT NULL UNIQUE,
    created_by              BIGINT NOT NULL REFERENCES users(id),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ NOT NULL,
    consumed_at             TIMESTAMPTZ,
    consumed_by_device_id   TEXT,
    note                    TEXT
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS enrollment_tokens;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
