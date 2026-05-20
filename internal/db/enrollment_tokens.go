package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnrollmentToken is the hub-side row. The raw token string is never stored
// — only the Argon2id (or equivalent) hash. The handler that mints the
// token returns the secret once and forgets it.
type EnrollmentToken struct {
	ID                   int64
	Hash                 string
	CreatedBy            int64
	CreatedAt            time.Time
	ExpiresAt            time.Time
	ConsumedAt           *time.Time
	ConsumedByDeviceID   *string // matches devices.id when consumed; loose, no FK
	Note                 string
}

type EnrollmentTokenStore struct {
	pool *pgxpool.Pool
}

func NewEnrollmentTokenStore(pool *pgxpool.Pool) *EnrollmentTokenStore {
	return &EnrollmentTokenStore{pool: pool}
}

// Create persists a freshly minted enrollment token. The TTL is enforced
// later at consumption time (expires_at column); the row stays in the table
// after expiry as audit trail.
func (s *EnrollmentTokenStore) Create(ctx context.Context, hash string, createdBy int64, ttl time.Duration, note string) (*EnrollmentToken, error) {
	const q = `
		INSERT INTO enrollment_tokens (hash, created_by, expires_at, note)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		RETURNING id, created_at, expires_at`
	t := &EnrollmentToken{Hash: hash, CreatedBy: createdBy, Note: note}
	err := s.pool.QueryRow(ctx, q, hash, createdBy, time.Now().Add(ttl), note).
		Scan(&t.ID, &t.CreatedAt, &t.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Consume atomically marks the token as used by the given device id.
// Returns ErrNotFound for any failing precondition — unknown hash, already
// consumed, or expired — so the register handler cannot leak which it was.
//
// The UPDATE … WHERE … RETURNING is the whole atomic step: no SELECT-then-
// UPDATE race; two simultaneous registrations with the same token can't
// both succeed.
func (s *EnrollmentTokenStore) Consume(ctx context.Context, hash, deviceID string) error {
	const q = `
		UPDATE enrollment_tokens
		SET consumed_at = now(), consumed_by_device_id = $2
		WHERE hash = $1
		  AND consumed_at IS NULL
		  AND expires_at > now()
		RETURNING id`
	var id int64
	err := s.pool.QueryRow(ctx, q, hash, deviceID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// List returns enrollment tokens, newest first. Used by the admin UI to
// show outstanding tokens and recent consumption history.
func (s *EnrollmentTokenStore) List(ctx context.Context) ([]*EnrollmentToken, error) {
	const q = `
		SELECT id, hash, created_by, created_at, expires_at,
		       consumed_at, consumed_by_device_id, COALESCE(note, '')
		FROM enrollment_tokens ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*EnrollmentToken, 0, 8)
	for rows.Next() {
		t := &EnrollmentToken{}
		if err := rows.Scan(&t.ID, &t.Hash, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt,
			&t.ConsumedAt, &t.ConsumedByDeviceID, &t.Note); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke marks a token as consumed without binding it to a device. Used
// when an admin issues a token by mistake and wants to invalidate it
// before it can be used. consumed_by_device_id stays NULL so a later
// audit can distinguish "consumed by enrollment" from "revoked".
func (s *EnrollmentTokenStore) Revoke(ctx context.Context, id int64) error {
	const q = `
		UPDATE enrollment_tokens
		SET consumed_at = now()
		WHERE id = $1 AND consumed_at IS NULL
		RETURNING id`
	var got int64
	err := s.pool.QueryRow(ctx, q, id).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
