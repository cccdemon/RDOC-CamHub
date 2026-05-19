package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/config"
	"github.com/raumdock/rdoc-camhub/internal/db"
	"github.com/raumdock/rdoc-camhub/internal/httpapi"
)

const version = "0.1.0-m0.5"

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"serve"}
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		exitOnErr(runServe(rest))
	case "migrate":
		exitOnErr(runMigrate(rest))
	case "bootstrap-admin":
		exitOnErr(runBootstrapAdmin(rest))
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		printHelp(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printHelp(os.Stderr)
		os.Exit(2)
	}
}

func runServe(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("serve takes no positional args (got %v)", args)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	if !cfg.CookieSecure {
		logger.Warn("CAMHUB_DEV_INSECURE_COOKIE=1 — Secure cookie attribute DISABLED. Do NOT run this in production.")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Apply pending migrations before opening the long-lived pool. Failing
	// here is the right place — we don't want to start serving requests
	// against a schema older than the binary expects.
	migrateCtx, cancelMig := context.WithTimeout(ctx, 60*time.Second)
	if err := db.Migrate(migrateCtx, cfg.DBURL); err != nil {
		cancelMig()
		return fmt.Errorf("migrate: %w", err)
	}
	cancelMig()

	pool, err := db.Open(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}
	defer pool.Close()

	cookies := httpapi.SessionCookieConfig{
		Secure: cfg.CookieSecure,
		Domain: cfg.CookieDomain,
	}

	srv := httpapi.New(logger, pool, version, httpapi.Options{
		Cookies:        cookies,
		TrustedProxies: cfg.TrustedProxies,
		AllowedOrigins: cfg.AllowedOrigins,
	})
	srv.LoginRateLimiter = httpapi.LoginRateLimiter(httpapi.RateLimitConfig{
		PerIP:      cfg.LoginRateLimitPerIP,
		WindowSecs: cfg.LoginRateLimitWindowSecs,
	})

	logger.Info("camhub starting",
		"version", version,
		"listen", cfg.Listen,
		"cookie_secure", cfg.CookieSecure,
		"cookie_domain", cfg.CookieDomain,
		"trusted_proxies", len(cfg.TrustedProxies),
		"allowed_origins", len(cfg.AllowedOrigins),
		"login_rate_per_ip", cfg.LoginRateLimitPerIP,
		"login_rate_window_secs", cfg.LoginRateLimitWindowSecs,
	)

	// Background session purge (PR-S5). RequireSession enforces expires_at
	// on every request, so a missed cycle is harmless — this just keeps the
	// table from growing unbounded. One immediate pass at startup so a
	// just-restarted hub clears any rows the previous instance would have
	// purged shortly.
	go func() {
		store := db.NewSessionStore(pool)
		runPurge := func() {
			n, err := store.PurgeExpired(ctx)
			switch {
			case err != nil:
				logger.Warn("session purge failed", "err", err)
			case n > 0:
				logger.Info("session purge", "removed", n)
			}
		}
		runPurge()
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runPurge()
			}
		}
	}()

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err, ok := <-serveErr:
		if ok && err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	}

	shutdownCtx, cancelShut := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelShut()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("graceful shutdown failed", "err", err)
	}
	return nil
}

func runMigrate(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: camhub migrate up|down")
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	switch args[0] {
	case "up":
		return db.Migrate(ctx, cfg.DBURL)
	case "down":
		return db.MigrateDown(ctx, cfg.DBURL)
	default:
		return fmt.Errorf("usage: camhub migrate up|down (got %q)", args[0])
	}
}

func printHelp(w *os.File) {
	fmt.Fprintf(w, `camhub %s

Usage:
  camhub [serve]                          run the HTTP server (default)
  camhub migrate up|down                  apply or roll back one migration
  camhub bootstrap-admin --email E --password P
                                          create the initial admin user
  camhub version                          print the build version
  camhub help                              print this message

Configuration is via env vars. See README.md.
`, version)
}

func exitOnErr(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "camhub: %v\n", err)
	os.Exit(1)
}
