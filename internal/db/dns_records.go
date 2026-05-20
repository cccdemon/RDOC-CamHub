package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DNSRecordType mirrors the CHECK constraint.
type DNSRecordType string

const (
	DNSTypeA    DNSRecordType = "A"
	DNSTypeAAAA DNSRecordType = "AAAA"
)

// DNSRecord ties a device to a single Cloudflare record. The pair
// (DeviceID, Type) is unique — a device has at most one A and one AAAA.
// CloudflareID is the load-bearing field: without it, on an IP change the
// hub would have to list-and-search Cloudflare's record set each time.
type DNSRecord struct {
	ID            int64
	DeviceID      string
	FQDN          string
	Type          DNSRecordType
	Value         string
	CloudflareID  string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type DNSRecordStore struct {
	pool *pgxpool.Pool
}

func NewDNSRecordStore(pool *pgxpool.Pool) *DNSRecordStore {
	return &DNSRecordStore{pool: pool}
}

// Upsert writes a (device_id, type) pair. On the second call for the same
// device+type, value and cloudflare_id are overwritten — useful when the
// cam's public IP changes and the hub does PUT against Cloudflare,
// receiving a (possibly new) record id back.
func (s *DNSRecordStore) Upsert(ctx context.Context, r *DNSRecord) error {
	const q = `
		INSERT INTO dns_records (device_id, fqdn, type, value, cloudflare_id)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (device_id, type) DO UPDATE SET
			fqdn          = EXCLUDED.fqdn,
			value         = EXCLUDED.value,
			cloudflare_id = EXCLUDED.cloudflare_id,
			updated_at    = now()
		RETURNING id, created_at, updated_at`
	return s.pool.QueryRow(ctx, q, r.DeviceID, r.FQDN, r.Type, r.Value, r.CloudflareID).
		Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
}

// ByDevice returns all (A + AAAA) records the hub holds for a device.
// Empty slice + nil error means no records exist yet — distinct from an
// error condition.
func (s *DNSRecordStore) ByDevice(ctx context.Context, deviceID string) ([]*DNSRecord, error) {
	const q = `
		SELECT id, device_id, fqdn, type, value, cloudflare_id, created_at, updated_at
		FROM dns_records WHERE device_id = $1 ORDER BY type`
	rows, err := s.pool.Query(ctx, q, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*DNSRecord, 0, 2)
	for rows.Next() {
		r := &DNSRecord{}
		if err := rows.Scan(&r.ID, &r.DeviceID, &r.FQDN, &r.Type, &r.Value, &r.CloudflareID, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns a single record by (device, type). ErrNotFound when missing
// — the typical case before initial enrollment for that record type.
func (s *DNSRecordStore) Get(ctx context.Context, deviceID string, t DNSRecordType) (*DNSRecord, error) {
	const q = `
		SELECT id, device_id, fqdn, type, value, cloudflare_id, created_at, updated_at
		FROM dns_records WHERE device_id = $1 AND type = $2`
	r := &DNSRecord{}
	err := s.pool.QueryRow(ctx, q, deviceID, t).
		Scan(&r.ID, &r.DeviceID, &r.FQDN, &r.Type, &r.Value, &r.CloudflareID, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Delete removes the local pointer for one (device, type). The caller is
// expected to have already deleted the actual Cloudflare record; this
// store does not call Cloudflare.
func (s *DNSRecordStore) Delete(ctx context.Context, deviceID string, t DNSRecordType) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM dns_records WHERE device_id = $1 AND type = $2`, deviceID, t)
	return err
}
