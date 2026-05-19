package db

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Session struct {
	ID          string
	UserID      int64
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RefreshedAt time.Time
	UserAgent   string
}

// SessionWithUser is the auth-middleware view: a not-yet-expired session
// joined with the user's email and role in a single round-trip. Used by
// RequireSession to build a Principal without a second DB call per request.
type SessionWithUser struct {
	Session
	UserEmail string
	UserRole  Role
}

type SessionStore struct {
	pool *pgxpool.Pool
}

func NewSessionStore(pool *pgxpool.Pool) *SessionStore { return &SessionStore{pool: pool} }

func (s *SessionStore) Create(ctx context.Context, id string, userID int64, ttl time.Duration, ua string, ip netip.Addr) error {
	const q = `INSERT INTO sessions (id, user_id, expires_at, user_agent, ip)
	           VALUES ($1, $2, $3, $4, $5)`
	var ipArg any
	if ip.IsValid() {
		ipArg = ip.String()
	}
	_, err := s.pool.Exec(ctx, q, id, userID, time.Now().Add(ttl), ua, ipArg)
	return err
}

// GetActiveWithUser returns the session plus its user, only if the session
// has not expired. ErrNotFound covers both "no such session" and "expired".
func (s *SessionStore) GetActiveWithUser(ctx context.Context, id string) (*SessionWithUser, error) {
	const q = `
		SELECT s.id, s.user_id, s.created_at, s.expires_at, s.refreshed_at,
		       COALESCE(s.user_agent, ''), u.email, u.role
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.id = $1 AND s.expires_at > now()`
	out := &SessionWithUser{}
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&out.ID, &out.UserID, &out.CreatedAt, &out.ExpiresAt, &out.RefreshedAt, &out.UserAgent,
		&out.UserEmail, &out.UserRole,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SessionStore) Get(ctx context.Context, id string) (*Session, error) {
	const q = `SELECT id, user_id, created_at, expires_at, refreshed_at, COALESCE(user_agent, '')
	           FROM sessions WHERE id = $1`
	out := &Session{}
	err := s.pool.QueryRow(ctx, q, id).Scan(&out.ID, &out.UserID, &out.CreatedAt, &out.ExpiresAt, &out.RefreshedAt, &out.UserAgent)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SessionStore) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

func (s *SessionStore) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
