package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Role         Role
	CreatedAt    time.Time
}

type UserStore struct {
	pool *pgxpool.Pool
}

func NewUserStore(pool *pgxpool.Pool) *UserStore { return &UserStore{pool: pool} }

func (s *UserStore) Create(ctx context.Context, email, passwordHash string, role Role) (*User, error) {
	const q = `INSERT INTO users (email, password_hash, role)
	           VALUES ($1, $2, $3)
	           RETURNING id, created_at`
	u := &User{Email: email, PasswordHash: passwordHash, Role: role}
	if err := s.pool.QueryRow(ctx, q, email, passwordHash, role).Scan(&u.ID, &u.CreatedAt); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserStore) ByEmail(ctx context.Context, email string) (*User, error) {
	const q = `SELECT id, email, password_hash, role, created_at FROM users WHERE email = $1`
	u := &User{}
	err := s.pool.QueryRow(ctx, q, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}
