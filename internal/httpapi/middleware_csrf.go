package httpapi

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"

	"github.com/raumdock/rdoc-camhub/internal/auth"
)

// RequireCSRF enforces double-submit CSRF protection on state-changing
// cookie-authenticated requests.
//
// Skipped automatically when:
//   - the method is safe (GET / HEAD / OPTIONS), or
//   - the request carries Authorization: Bearer <token> (PAT path —
//     PATs are origin-independent and aren't subject to CSRF).
//
// Otherwise the request must carry:
//   - a camhub_csrf cookie, AND
//   - an X-CSRF-Token header whose value matches the cookie
//     (constant-time comparison), AND
//   - if AllowedOrigins is non-empty, an Origin or Referer header whose
//     origin is in the allow-list. An empty AllowedOrigins disables the
//     Origin check (the token alone gates the request).
//
// Cookie-only or header-only requests fail with 403.
func (s *Server) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if isBearerAuth(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !s.requestOriginAllowed(r) {
			writeError(w, http.StatusForbidden, "csrf_origin", "origin not allowed")
			return
		}
		cookie, err := r.Cookie(auth.CSRFCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusForbidden, "csrf_missing", "csrf cookie missing")
			return
		}
		header := r.Header.Get(auth.CSRFHeaderName)
		if header == "" {
			writeError(w, http.StatusForbidden, "csrf_missing", "csrf header missing")
			return
		}
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			writeError(w, http.StatusForbidden, "csrf_mismatch", "csrf token mismatch")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

func isBearerAuth(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// requestOriginAllowed returns true when Server.AllowedOrigins is empty
// (defense-in-depth disabled) OR the request's Origin/Referer origin
// matches an entry verbatim.
func (s *Server) requestOriginAllowed(r *http.Request) bool {
	if len(s.AllowedOrigins) == 0 {
		return true
	}
	got := requestOrigin(r)
	if got == "" {
		return false
	}
	for _, a := range s.AllowedOrigins {
		if got == a {
			return true
		}
	}
	return false
}

// requestOrigin returns the Origin header verbatim, or — if absent — the
// scheme+host portion of the Referer. Returns "" if neither is usable.
func requestOrigin(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" {
		return o
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
