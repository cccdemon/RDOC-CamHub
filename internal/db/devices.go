package db

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DeviceStatus mirrors the CHECK constraint on devices.status. The state
// machine: enrolled (after register) → online (first heartbeat) → stale
// (>5 min silent) → offline (>15 min). Computed by a background sweep,
// not by the heartbeat handler — see §4.2.
type DeviceStatus string

const (
	DeviceEnrolled DeviceStatus = "enrolled"
	DeviceOnline   DeviceStatus = "online"
	DeviceStale    DeviceStatus = "stale"
	DeviceOffline  DeviceStatus = "offline"
)

// Device is the in-Go view of a row in devices. Capabilities and Ports are
// kept as raw JSON so the hub doesn't need to track every cam-side schema
// bump — the UI/handlers re-decode as they need fields.
type Device struct {
	ID            string
	Name          string
	Subdomain     string
	DeviceJWTKID  string
	Capabilities  json.RawMessage
	Ports         json.RawMessage
	PublicIP      netip.Addr // zero value = no IPv4 reported
	PublicIPv6    netip.Addr // zero value = no IPv6 reported
	Status        DeviceStatus
	StreamHealth  string
	CamVersion    string
	LastSeenAt    *time.Time // nil until first heartbeat
	EnrolledAt    time.Time
	UpdatedAt     time.Time
}

// DeviceRegistration is the input shape for Create. Mirrors the cam-side
// POST /v1/devices/register body plus the hub-derived subdomain and kid.
// Kept as a struct so callers don't bind positional arg order to the SQL.
type DeviceRegistration struct {
	ID            string
	Name          string
	Subdomain     string
	DeviceJWTKID  string
	Capabilities  json.RawMessage
	Ports         json.RawMessage
	PublicIP      netip.Addr
	PublicIPv6    netip.Addr
}

// HeartbeatUpdate is the input shape for UpdateHeartbeat — only fields the
// cam can change at heartbeat time. Status transitions live in the
// background sweep, not here, so the cam can't claim itself "online".
type HeartbeatUpdate struct {
	PublicIP     netip.Addr
	PublicIPv6   netip.Addr
	StreamHealth string
	CamVersion   string
}

type DeviceStore struct {
	pool *pgxpool.Pool
}

func NewDeviceStore(pool *pgxpool.Pool) *DeviceStore { return &DeviceStore{pool: pool} }

// Create inserts a freshly enrolled device. Caller has already resolved the
// subdomain (collision-suffixed if needed) and signed the device JWT — this
// is purely a persistence step. The unique constraint on subdomain is the
// last line of defense; a returned 23505 means a parallel enrollment won
// the race for the same subdomain.
func (s *DeviceStore) Create(ctx context.Context, reg *DeviceRegistration) (*Device, error) {
	const q = `
		INSERT INTO devices (
			id, name, subdomain, device_jwt_kid,
			capabilities, ports, public_ip, public_ipv6
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING enrolled_at, updated_at`
	d := &Device{
		ID:           reg.ID,
		Name:         reg.Name,
		Subdomain:    reg.Subdomain,
		DeviceJWTKID: reg.DeviceJWTKID,
		Capabilities: emptyJSONIfNil(reg.Capabilities),
		Ports:        emptyJSONIfNil(reg.Ports),
		PublicIP:     reg.PublicIP,
		PublicIPv6:   reg.PublicIPv6,
		Status:       DeviceEnrolled,
	}
	err := s.pool.QueryRow(ctx, q,
		reg.ID, reg.Name, reg.Subdomain, reg.DeviceJWTKID,
		d.Capabilities, d.Ports,
		ipOrNil(reg.PublicIP), ipOrNil(reg.PublicIPv6),
	).Scan(&d.EnrolledAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// GetByID returns a single device. ErrNotFound for unknown id.
//
// host(public_ip) in the SELECT strips the /32 prefix Postgres would
// otherwise emit for an INET-as-host, so scanning into *string yields a
// clean "192.0.2.1" that netip.ParseAddr accepts.
func (s *DeviceStore) GetByID(ctx context.Context, id string) (*Device, error) {
	const q = `
		SELECT id, name, subdomain, device_jwt_kid,
		       capabilities, ports,
		       host(public_ip), host(public_ipv6),
		       status, COALESCE(stream_health, ''), COALESCE(cam_version, ''),
		       last_seen_at, enrolled_at, updated_at
		FROM devices WHERE id = $1`
	return s.scanOne(s.pool.QueryRow(ctx, q, id))
}

// BySubdomain is the conflict-check during enrollment. Returns ErrNotFound
// if the subdomain is free.
func (s *DeviceStore) BySubdomain(ctx context.Context, sub string) (*Device, error) {
	const q = `
		SELECT id, name, subdomain, device_jwt_kid,
		       capabilities, ports,
		       host(public_ip), host(public_ipv6),
		       status, COALESCE(stream_health, ''), COALESCE(cam_version, ''),
		       last_seen_at, enrolled_at, updated_at
		FROM devices WHERE subdomain = $1`
	return s.scanOne(s.pool.QueryRow(ctx, q, sub))
}

// List returns every device in enrollment order. Cheap until we have
// hundreds of cams; paginate when that becomes a real concern.
func (s *DeviceStore) List(ctx context.Context) ([]*Device, error) {
	const q = `
		SELECT id, name, subdomain, device_jwt_kid,
		       capabilities, ports,
		       host(public_ip), host(public_ipv6),
		       status, COALESCE(stream_health, ''), COALESCE(cam_version, ''),
		       last_seen_at, enrolled_at, updated_at
		FROM devices ORDER BY enrolled_at ASC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*Device, 0, 16)
	for rows.Next() {
		d, err := s.scanOne(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateHeartbeat records a cam's periodic check-in. last_seen_at is
// always bumped; IPs are overwritten unconditionally (treating the cam as
// the source of truth on its own public addresses). Status is recomputed
// to 'online' here because heartbeat by definition proves liveness — the
// stale/offline transitions happen in a separate sweep.
//
// Returns the new last_seen_at so the caller can compare against the
// previous value (e.g. to decide whether to call Cloudflare).
func (s *DeviceStore) UpdateHeartbeat(ctx context.Context, id string, h *HeartbeatUpdate) (time.Time, error) {
	const q = `
		UPDATE devices SET
			public_ip      = COALESCE($2::inet, public_ip),
			public_ipv6    = COALESCE($3::inet, public_ipv6),
			stream_health  = NULLIF($4, ''),
			cam_version    = NULLIF($5, ''),
			status         = 'online',
			last_seen_at   = now(),
			updated_at     = now()
		WHERE id = $1
		RETURNING last_seen_at`
	var lastSeen time.Time
	err := s.pool.QueryRow(ctx, q, id,
		ipOrNil(h.PublicIP), ipOrNil(h.PublicIPv6),
		h.StreamHealth, h.CamVersion,
	).Scan(&lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	if err != nil {
		return time.Time{}, err
	}
	return lastSeen, nil
}

// MarkStale flips devices that haven't been heard from in the given
// `staleAfter` window from 'online' to 'stale', and the same for
// 'offline' beyond `offlineAfter`. Returns counts so the caller can log.
//
// Cutoffs are computed in Go and passed as timestamps so we don't depend
// on Postgres parsing a Go duration string. Run on a ticker (10–30 s)
// from main; cheap two-statement update.
func (s *DeviceStore) MarkStale(ctx context.Context, staleAfter, offlineAfter time.Duration) (stale, offline int64, err error) {
	now := time.Now()
	offlineCutoff := now.Add(-offlineAfter)
	staleCutoff := now.Add(-staleAfter)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)

	const qOffline = `
		UPDATE devices
		SET status = 'offline', updated_at = now()
		WHERE status IN ('online', 'stale')
		  AND last_seen_at IS NOT NULL
		  AND last_seen_at < $1`
	const qStale = `
		UPDATE devices
		SET status = 'stale', updated_at = now()
		WHERE status = 'online'
		  AND last_seen_at IS NOT NULL
		  AND last_seen_at < $1`
	// Run the offline sweep FIRST so anything past the offline threshold
	// doesn't get marked 'stale' on the way through.
	offTag, err := tx.Exec(ctx, qOffline, offlineCutoff)
	if err != nil {
		return 0, 0, err
	}
	staleTag, err := tx.Exec(ctx, qStale, staleCutoff)
	if err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return staleTag.RowsAffected(), offTag.RowsAffected(), nil
}

// Delete removes a device row. The dns_records FK is ON DELETE CASCADE so
// the per-device DNS pointers vanish too; the caller is responsible for
// having already deleted the actual Cloudflare records before calling
// this (otherwise the records leak in Cloudflare).
func (s *DeviceStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scannable matches both *pgx.Row and pgx.Rows so scanOne works for
// QueryRow and Query iteration alike.
type scannable interface {
	Scan(dest ...any) error
}

func (s *DeviceStore) scanOne(row scannable) (*Device, error) {
	var (
		d            Device
		publicIP     *string
		publicIPv6   *string
		lastSeen     *time.Time
	)
	err := row.Scan(
		&d.ID, &d.Name, &d.Subdomain, &d.DeviceJWTKID,
		&d.Capabilities, &d.Ports,
		&publicIP, &publicIPv6,
		&d.Status, &d.StreamHealth, &d.CamVersion,
		&lastSeen, &d.EnrolledAt, &d.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.LastSeenAt = lastSeen
	if publicIP != nil {
		if addr, perr := netip.ParseAddr(*publicIP); perr == nil {
			d.PublicIP = addr
		}
	}
	if publicIPv6 != nil {
		if addr, perr := netip.ParseAddr(*publicIPv6); perr == nil {
			d.PublicIPv6 = addr
		}
	}
	return &d, nil
}

// ipOrNil converts a netip.Addr to a *string for pgx parameter binding:
// the zero value becomes SQL NULL, anything else stringifies. We pass it
// as a string (not netip.Addr) because pgx's INET type binding for
// netip.Addr was added later; the string path works on every pgx version
// the project pins.
func ipOrNil(a netip.Addr) any {
	if !a.IsValid() {
		return nil
	}
	return a.String()
}

func emptyJSONIfNil(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return raw
}
