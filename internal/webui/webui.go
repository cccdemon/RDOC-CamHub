// Package webui serves the HTML UI for CamHub on app.camhub.raumdock.org.
//
// Plan §17 picked templ + htmx as the long-term stack. UI-M0 uses
// html/template instead — two templates (layout + login) don't justify a
// codegen step, and the scratch image stays single-build. Move to templ
// when UI-M1 lands cam cards, status chips, and polling partials where
// the component model starts to pay for the tooling cost.
//
// Surface:
//   - GET /login        public login form
//   - GET /             session-gated landing (dashboard stub for UI-M0)
//   - GET /static/*     embedded CSS / JS / fonts / favicon
//
// The HTML form POSTs to /v1/auth/login (same-origin in dev; the
// AppHost/ApiHost split in production rewires this through
// <meta name="api-base"> read by static/js/camhub.js).
package webui

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed all:static
var staticFS embed.FS

// Server owns the rendered template set and the embedded asset FS. It does
// not own session lookup — page-level auth gating is wired by the caller
// via the same RequireSession middleware the JSON API uses.
type Server struct {
	Logger    *slog.Logger
	Templates *Templates

	// APIBase is the absolute origin the login form posts to and the JS
	// refresh ticker hits. Empty means "same origin" (dev). In production
	// this is "https://api.camhub.raumdock.org".
	APIBase string

	// AppVersion is rendered in the footer for ops visibility.
	AppVersion string
}

// New constructs a Server with templates parsed up-front so render errors
// surface at startup, not on first page view.
func New(logger *slog.Logger, apiBase, version string) (*Server, error) {
	tpl, err := loadTemplates(templatesFS)
	if err != nil {
		return nil, err
	}
	return &Server{
		Logger:     logger,
		Templates:  tpl,
		APIBase:    apiBase,
		AppVersion: version,
	}, nil
}

// StaticFS returns the embedded /static subtree as an io/fs. The caller
// mounts it with http.FileServer + http.StripPrefix("/static", ...).
func (s *Server) StaticFS() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// embed guarantees the subdirectory exists; this is a
		// programmer-error path that should never trigger at runtime.
		panic("webui: static/ subtree missing from embed: " + err.Error())
	}
	return sub
}

// StaticHandler is the conventional /static/* handler with the right
// Cache-Control. UI-M0 uses a conservative TTL; UI-M4 will introduce
// build-hash URLs (§17.7 q4) and bump this to immutable.
func (s *Server) StaticHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.StaticFS()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		fileServer.ServeHTTP(w, r)
	})
}
