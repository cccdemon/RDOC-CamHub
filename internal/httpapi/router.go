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

// SessionWriter is what the HTTP layer needs from the session store. Same
// rationale as UserLookup — interface for test injection. *db.SessionStore
// satisfies it.
type SessionWriter interface {
	Create(ctx context.Context, id string, userID int64, ttl time.Duration, ua string, ip netip.Addr) error
	Get(ctx context.Context, id string) (*db.Session, error)
	GetActiveWithUser(ctx context.Context, id string) (*db.SessionWithUser, error)
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
	AllowedOrigins []string

	// LoginRateLimiter is set by PR-S2. Optional; nil disables rate limiting.
	LoginRateLimiter func(http.Handler) http.Handler
}

type Options struct {
	Cookies        SessionCookieConfig
	TrustedProxies []netip.Prefix
	AllowedOrigins []string
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
		AllowedOrigins: opts.AllowedOrigins,
	}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(TrustedProxyIP(s.TrustedProxies))
	r.Use(s.logRequests)
	r.Use(middleware.Recoverer)

	// Public routes — no session required.
	r.Group(func(r chi.Router) {
		r.Get("/healthz", s.healthz)
		r.Route("/v1/auth", func(r chi.Router) {
			if s.LoginRateLimiter != nil {
				r.With(s.LoginRateLimiter).Post("/login", s.login)
			} else {
				r.Post("/login", s.login)
			}
			// Logout is intentionally public: with SameSite=Lax cookies, a
			// cross-site POST cannot carry the session cookie, so an
			// attacker cannot force-logout a victim. Making it public also
			// lets a stale-cookie holder clear their state cleanly.
			r.Post("/logout", s.logout)
		})
	})

	// Authenticated routes — any logged-in user (viewer/operator/admin).
	// RequireCSRF is a no-op for GET/HEAD/OPTIONS and for Bearer-auth
	// requests; the only state-changing cookie-auth endpoints (currently
	// none) get double-submit token enforcement.
	r.Group(func(r chi.Router) {
		r.Use(s.RequireSession)
		r.Use(s.RequireCSRF)
		r.Get("/v1/auth/me", s.me)
	})

	// Admin routes — declared now so future endpoints land in the right
	// group. Empty in PR-S3; CSRF middleware pre-wired so M1 admin POSTs
	// inherit it automatically.
	r.Group(func(r chi.Router) {
		r.Use(s.RequireSession)
		r.Use(RequireRole(db.RoleAdmin))
		r.Use(s.RequireCSRF)
		// (no admin endpoints yet)
	})

	return r
}
