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
	"github.com/raumdock/rdoc-camhub/internal/webui"
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
	// Rotate is the backing operation for POST /v1/auth/refresh. See
	// db.SessionStore.Rotate for the semantics (hard cap on
	// createdAt + refreshWindow; access-expired but in-window allowed).
	Rotate(ctx context.Context, oldID, newID string, accessTTL, refreshWindow time.Duration) (*db.Session, error)
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

	// Two-origin deployment shape (Plan §17.1). Both empty = dev:
	// the UI routes are mounted on the same mux as the API, browseable
	// at http://localhost:8080/login. Both set = production: the
	// HostRouter splits traffic and each surface 404s the other's paths.
	AppHost string
	APIHost string

	// WebUI is the rendered HTML surface. Nil when webui isn't wired
	// (legacy tests); Router() then serves the JSON-only mux.
	WebUI *webui.Server

	// LoginRateLimiter is set by PR-S2. Optional; nil disables rate limiting.
	LoginRateLimiter func(http.Handler) http.Handler
}

type Options struct {
	Cookies        SessionCookieConfig
	TrustedProxies []netip.Prefix
	AllowedOrigins []string

	// AppHost / APIHost gate the host-aware split. Setting only one is
	// a configuration error and triggers a panic in Router().
	AppHost string
	APIHost string

	// WebUI is the configured UI server (templates loaded). Nil = no UI
	// served; the JSON API surface is the entire mux.
	WebUI *webui.Server
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
		AppHost:        opts.AppHost,
		APIHost:        opts.APIHost,
		WebUI:          opts.WebUI,
	}
}

func (s *Server) Router() http.Handler {
	// Reject half-configured deployments early. AppHost without APIHost
	// (or vice versa) would silently misroute requests in prod.
	if (s.AppHost == "") != (s.APIHost == "") {
		panic("httpapi: AppHost and APIHost must be set together (or both empty)")
	}

	// No UI configured at all → JSON-only listener. Used by tests and
	// older configs that never opted in to the UI surface.
	if s.WebUI == nil {
		return s.apiRouter()
	}

	// Dev mode: AppHost/APIHost unset, so both surfaces live on a single
	// mux. We register the UI routes directly on the API mux (rather
	// than mounting a separate mux) to avoid running the global
	// middleware chain twice.
	if s.AppHost == "" {
		r := s.apiRouter()
		s.attachWebUIRoutes(r)
		return r
	}

	// Prod: each surface answers only its own paths.
	return &webui.HostRouter{
		AppHost:    s.AppHost,
		APIHost:    s.APIHost,
		UIHandler:  s.webuiRouter(),
		APIHandler: s.apiRouter(),
	}
}

// apiRouter builds the JSON/control surface. Identical to the historical
// Router() — the UI work didn't touch the API contract.
func (s *Server) apiRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(TrustedProxyIP(s.TrustedProxies))
	r.Use(s.logRequests)
	r.Use(middleware.Recoverer)
	// CORS sits early so OPTIONS preflights short-circuit before any
	// rate-limit or session-lookup work. No-op when AllowedOrigins is
	// empty (dev path).
	r.Use(s.CORS)

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
			// Refresh is public for the same reason: the cookie itself is
			// the credential, and SameSite=Lax blocks the cross-site CSRF
			// vector. Putting refresh behind RequireSession would defeat
			// its purpose (renewing an access-expired session).
			r.Post("/refresh", s.refresh)
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

// webuiRouter builds the HTML surface for app.camhub.raumdock.org. Plan
// §17.4. Pre-session pages use cookie-presence redirects (see
// webui.RequireSessionCookie); actual session validation happens on the
// first XHR (camhub.js) and returns the user to /login on 401.
func (s *Server) webuiRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(TrustedProxyIP(s.TrustedProxies))
	r.Use(s.logRequests)
	r.Use(middleware.Recoverer)

	// Healthz on the UI host too — Caddy can probe either.
	r.Get("/healthz", s.healthz)

	s.attachWebUIRoutes(r)
	return r
}

// attachWebUIRoutes registers the HTML/static routes onto an existing
// router. Used both by webuiRouter (prod, host-split) and by the dev
// path on the API mux. The router must already have the global
// middleware chain wired.
func (s *Server) attachWebUIRoutes(r chi.Router) {
	// Static assets are public + cacheable.
	r.Mount("/static", http.StripPrefix("/static", s.WebUI.StaticHandler()))

	// Login: signed-in users go straight to /.
	r.With(webui.RedirectIfAuthenticated("/")).Get("/login", s.WebUI.LoginPage)

	// Dashboard (UI-M0 stub). Cookie presence required; XHR-driven
	// validation happens client-side.
	r.With(webui.RequireSessionCookie).Get("/", s.WebUI.Dashboard)
}
