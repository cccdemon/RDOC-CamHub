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

// Rotate atomically swaps a session's id, resets refreshed_at + expires_at,
// and returns the resulting row. It is the single backing operation for
// POST /v1/auth/refresh.
//
// The refresh-window check (created_at + window > now()) is the hard cap:
// once a session is older than the window it cannot be rotated even if the
// caller still holds the cookie. Beyond that it is up to RequireSession to
// guard the access TTL (expires_at) on subsequent requests.
//
// expires_at itself is NOT checked here on purpose: refresh is the
// mechanism for renewing an access-expired session within the refresh
// window. Checking it would force the UI to refresh strictly before the
// access TTL elapses with zero tolerance for clock skew or latency.
//
// Returns ErrNotFound if the id is unknown OR the session is outside the
// refresh window — same response for both so callers can collapse them
// into one 401 without leaking which.
func (s *SessionStore) Rotate(ctx context.Context, oldID, newID string, accessTTL, refreshWindow time.Duration) (*Session, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		userID    int64
		createdAt time.Time
		userAgent string
	)
	const selectQ = `SELECT user_id, created_at, COALESCE(user_agent, '')
	                 FROM sessions WHERE id = $1 FOR UPDATE`
	if err := tx.QueryRow(ctx, selectQ, oldID).Scan(&userID, &createdAt, &userAgent); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Hard cap. Compared in Go to keep the SQL portable across deployments
	// that might have clock-drift between app and DB.
	if time.Since(createdAt) > refreshWindow {
		return nil, ErrNotFound
	}

	now := time.Now()
	newExpires := now.Add(accessTTL)
	const updateQ = `UPDATE sessions
	                 SET id = $1, refreshed_at = $2, expires_at = $3
	                 WHERE id = $4`
	if _, err := tx.Exec(ctx, updateQ, newID, now, newExpires, oldID); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &Session{
		ID:          newID,
		UserID:      userID,
		CreatedAt:   createdAt,
		RefreshedAt: now,
		ExpiresAt:   newExpires,
		UserAgent:   userAgent,
	}, nil
}
