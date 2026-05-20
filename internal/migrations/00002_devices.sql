-- +goose Up
-- +goose StatementBegin

-- devices is the registry of enrolled cams. Plan §4.1, §9.
--
-- id is the cam-supplied device_id (UUID or hostname-based string). Keeping
-- it TEXT rather than auto-numeric lets the cam own its identity across
-- re-enrollments without the hub re-issuing keys.
--
-- subdomain is the hub-assigned name (preferred_name with optional `-2`,
-- `-3` suffix on conflict, per §3 and §15-Q1). UNIQUE because that's the
-- whole point — public DNS rests on it.
--
-- device_jwt_kid records which signing-key generation issued this device's
-- JWT. We use it during the retirement window (§4.3) to flag devices that
-- still hold tokens signed by a kid we're about to refuse.
--
-- capabilities is the cam-supplied descriptor (§4.4) stored verbatim;
-- we never validate fields beyond JSON shape. JSONB so the UI can query
-- e.g. controls @> '["pan"]' once we surface filters.
--
-- ports captures the cam-reported {webrtc, hls, rtmp} integers so the
-- OBS-URL generator (Milestone 2) can build correct stream URLs.
--
-- status starts at 'enrolled' on register, flips to 'online' on first
-- heartbeat, then walks to 'stale' (>5 min silent) / 'offline' (>15 min)
-- per §4.2. last_seen_at drives that state machine.
CREATE TABLE devices (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    subdomain           TEXT NOT NULL UNIQUE,
    device_jwt_kid      TEXT NOT NULL,
    capabilities        JSONB NOT NULL DEFAULT '{}'::jsonb,
    ports               JSONB NOT NULL DEFAULT '{}'::jsonb,
    public_ip           INET,
    public_ipv6         INET,
    status              TEXT NOT NULL DEFAULT 'enrolled'
                            CHECK (status IN ('enrolled', 'online', 'stale', 'offline')),
    stream_health       TEXT,
    cam_version         TEXT,
    last_seen_at        TIMESTAMPTZ,
    enrolled_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_devices_last_seen ON devices(last_seen_at);
CREATE INDEX idx_devices_status    ON devices(status);

-- dns_records ties each device to the Cloudflare record IDs the hub created
-- on its behalf. We need cloudflare_id (returned by the CF API on POST) to
-- run a targeted PUT when the cam's public IP changes on a later heartbeat
-- — without it we'd have to list-and-search every time.
--
-- A device can have at most one A and one AAAA record at a time, so
-- (device_id, type) is UNIQUE. ON DELETE CASCADE means an admin deleting
-- a device row clears the local pointers (the actual CF records must be
-- deleted via the CF API in a coordinated tx — the store enforces that
-- order, see DeviceStore.Delete).
CREATE TABLE dns_records (
    id              BIGSERIAL PRIMARY KEY,
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    fqdn            TEXT NOT NULL,
    type            TEXT NOT NULL CHECK (type IN ('A', 'AAAA')),
    value           TEXT NOT NULL,
    cloudflare_id   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, type)
);
CREATE INDEX idx_dns_records_device ON dns_records(device_id);

-- enrollment_tokens was created in 00001 without an FK from
-- consumed_by_device_id back to devices because the table didn't exist
-- yet. We intentionally do NOT add an FK now either:
--
--   - Keeping it loose preserves the audit trail when a device is later
--     deleted (a deleted-cam row would otherwise orphan its origin
--     enrollment token).
--   - The reverse query (who issued this device?) is cheap by string id.
--
-- Plan §16 (security baseline) calls for this loose coupling explicitly.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dns_records;
DROP TABLE IF EXISTS devices;
-- +goose StatementEnd
