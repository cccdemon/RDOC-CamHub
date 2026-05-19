package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/raumdock/rdoc-camhub/internal/db"
)

// UserLookup is the slice of *db.UserStore that the HTTP layer depends on.
// Kept as an interface so handler tests can inject a stub without standing
// up Postgres. *db.UserStore satisfies it.
type UserLookup interface {
	ByEmail(ctx context.Context, email string) (*db.User, error)
}

// SessionWriter is what login needs from the session store. Same rationale.
type SessionWriter interface {
	Create(ctx context.Context, id string, userID int64, ttl time.Duration, ua string, ip netip.Addr) error
	Get(ctx context.Context, id string) (*db.Session, error)
	Delete(ctx context.Context, id string) error
}

type Server struct {
	Logger         *slog.Logger
	Pool           *pgxpool.Pool
	Users          UserLookup
	Sessions       SessionWriter
	Version        string
	Cookies        SessionCookieConfig
	TrustedProxies []netip.Prefix

	// LoginRateLimiter is set by PR-S2. Optional; nil disables rate limiting.
	LoginRateLimiter func(http.Handler) http.Handler
}

type Options struct {
	Cookies        SessionCookieConfig
	TrustedProxies []netip.Prefix
}

func New(logger *slog.Logger, pool *pgxpool.Pool, version string, opts Options) *Server {
	return &Server{
		Logger:         logger,
		Pool:           pool,
		Users:          db.NewUserStore(pool),
		Sessions:       db.NewSessionStore(pool),
		Version:        version,
		Cookies:        opts.Cookies,
		TrustedProxies: opts.TrustedProxies,
	}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(TrustedProxyIP(s.TrustedProxies))
	r.Use(s.logRequests)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", s.healthz)

	r.Route("/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			if s.LoginRateLimiter != nil {
				r.With(s.LoginRateLimiter).Post("/login", s.login)
			} else {
				r.Post("/login", s.login)
			}
			r.Post("/logout", s.logout)
			r.Get("/me", s.me)
		})
	})

	return r
}
