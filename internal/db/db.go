package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/raumdock/rdoc-camhub/internal/migrations"
)

// Open returns a connection pool. It pings once with a short timeout so the
// caller fails fast on misconfiguration rather than at the first query.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

// Migrate runs all pending up migrations against the DSN.
func Migrate(ctx context.Context, dsn string) error {
	sqlDB, err := openStdlib(dsn)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set dialect: %w", err)
	}
	if err := goose.UpContext(ctx, sqlDB, "."); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}

// MigrateDown rolls back one migration.
func MigrateDown(ctx context.Context, dsn string) error {
	sqlDB, err := openStdlib(dsn)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set dialect: %w", err)
	}
	if err := goose.DownContext(ctx, sqlDB, "."); err != nil {
		return fmt.Errorf("goose down: %w", err)
	}
	return nil
}

func openStdlib(dsn string) (*sql.DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	connStr := stdlib.RegisterConnConfig(cfg.ConnConfig)
	sqlDB, err := sql.Open("pgx", connStr)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return sqlDB, nil
}

var ErrNotFound = errors.New("not found")
