package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/config"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// Mirrors the live login handler's pre-Argon2 cap. Bumping this here without
// bumping the handler would let an admin set a password they can never use.
const minPasswordLen = 12

func runBootstrapAdmin(args []string) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	email := fs.String("email", "", "admin email address")
	password := fs.String("password", "", "admin password (min 12 chars). Will be Argon2id-hashed before storage.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || *password == "" {
		fs.Usage()
		return errors.New("--email and --password are required")
	}
	if len(*password) < minPasswordLen {
		return fmt.Errorf("--password must be at least %d characters", minPasswordLen)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Idempotent: re-running bootstrap-admin against an up-to-date DB is a
	// no-op for the schema, and the unique-email constraint surfaces a clear
	// error if the user already exists.
	if err := db.Migrate(ctx, cfg.DBURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	pool, err := db.Open(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}
	defer pool.Close()

	hash, err := auth.HashPassword(*password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	normalizedEmail := strings.ToLower(strings.TrimSpace(*email))
	users := db.NewUserStore(pool)
	u, err := users.Create(ctx, normalizedEmail, hash, db.RoleAdmin)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	fmt.Printf("created admin user: id=%d email=%s role=%s\n", u.ID, u.Email, u.Role)
	return nil
}
