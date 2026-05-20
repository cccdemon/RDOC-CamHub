package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/config"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// runEnrollmentToken implements `camhub enrollment-token` — admin CLI
// for minting a one-shot device-enrollment token before the UI-M1 admin
// page lands (Plan §4.1).
//
// The output is the raw token on its own line so it composes cleanly
// with `>>` into a cam's /opt/server-tech/.env. Everything else
// (warnings, expiry, attribution) goes to stderr.
func runEnrollmentToken(args []string) error {
	fs := flag.NewFlagSet("enrollment-token", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	ttl := fs.Duration("ttl", 24*time.Hour, "token lifetime (default 24h, matches Plan §4.1)")
	note := fs.String("note", "", "free-text note for the audit trail (e.g. 'garage cam, ordered 2026-05-20')")
	actor := fs.String("actor-email", "", "admin email to attribute the token to (default: first admin in DB)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ttl <= 0 {
		return errors.New("--ttl must be positive")
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}
	defer pool.Close()

	actorEmail := strings.TrimSpace(strings.ToLower(*actor))
	actorID, resolvedEmail, err := resolveActor(ctx, pool, actorEmail)
	if err != nil {
		return err
	}

	raw, hash, err := auth.NewEnrollmentToken()
	if err != nil {
		return fmt.Errorf("mint token: %w", err)
	}

	store := db.NewEnrollmentTokenStore(pool)
	t, err := store.Create(ctx, hash, actorID, *ttl, *note)
	if err != nil {
		return fmt.Errorf("persist token: %w", err)
	}

	// stderr: warnings + metadata. stdout: just the token, so callers
	// can pipe it without sed/grep contortions.
	fmt.Fprintln(os.Stderr, "# IMPORTANT: this token is shown only once. Re-running this command mints a NEW token.")
	fmt.Fprintf(os.Stderr, "# id=%d  actor=%s  expires=%s\n", t.ID, resolvedEmail, t.ExpiresAt.Format(time.RFC3339))
	if *note != "" {
		fmt.Fprintf(os.Stderr, "# note=%q\n", *note)
	}
	fmt.Println(raw)
	return nil
}

// resolveActor turns the --actor-email flag (possibly empty) into a user
// id. Empty falls back to the first admin in the DB so a freshly
// bootstrapped hub doesn't require an extra flag for the common case of
// "single admin, just minted by bootstrap-admin".
//
// Returns the resolved email so the CLI can echo the attribution
// (whether explicit or fallback) on stderr.
func resolveActor(ctx context.Context, pool *pgxpool.Pool, email string) (int64, string, error) {
	if email == "" {
		var (
			id    int64
			found string
		)
		const q = `SELECT id, email FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1`
		if err := pool.QueryRow(ctx, q).Scan(&id, &found); err != nil {
			return 0, "", fmt.Errorf("look up first admin: %w (hint: run bootstrap-admin first, or pass --actor-email)", err)
		}
		return id, found, nil
	}
	users := db.NewUserStore(pool)
	u, err := users.ByEmail(ctx, email)
	if err != nil {
		return 0, "", fmt.Errorf("look up admin %q: %w", email, err)
	}
	if u.Role != db.RoleAdmin {
		return 0, "", fmt.Errorf("user %q is role %q, not admin", email, u.Role)
	}
	return u.ID, u.Email, nil
}
