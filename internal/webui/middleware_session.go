package webui

import (
	"net/http"

	"github.com/raumdock/rdoc-camhub/internal/auth"
)

// RequireSessionCookie redirects to /login when no session cookie is
// present. It deliberately does NOT validate the cookie against the
// session store — that would couple the webui package to the DB. Cookie
// validity is enforced by the first authenticated XHR (/v1/auth/me or a
// device endpoint); a 401 there triggers the client-side redirect in
// camhub.js. The cookie-presence check here is just to avoid rendering
// the dashboard for the obviously-unauthenticated visitor.
//
// Sessions invalidated server-side (rotated, deleted, expired beyond the
// refresh window) still carry the stale cookie value briefly; the dash
// will render, then the silent-refresh ticker's 401 sends them to /login.
// Acceptable tradeoff for UI-M0.
func RequireSessionCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.SessionCookieName)
		if err != nil || c.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RedirectIfAuthenticated sends already-signed-in visitors away from
// /login. Same caveat as RequireSessionCookie: presence-only, not
// validity. A stale cookie may bounce a user to / and immediately back
// when the dashboard's first XHR returns 401, but that's a single round
// trip and avoids two pages of "are you sure you want to sign in".
func RedirectIfAuthenticated(target string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c, err := r.Cookie(auth.SessionCookieName); err == nil && c.Value != "" {
				http.Redirect(w, r, target, http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
