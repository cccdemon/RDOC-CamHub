package httpapi

import (
	"net/http"

	"github.com/raumdock/rdoc-camhub/internal/auth"
)

// CORS enforces a strict same-origin-allow-list policy for cross-origin
// requests from the UI host (app.camhub.raumdock.org) to the API host
// (api.camhub.raumdock.org). Plan §17.1.
//
// Rules:
//   - The Origin response header is echoed back from the request only if
//     it appears in AllowedOrigins. No wildcard, no header-reflection-of-
//     anything-the-browser-sent (that would defeat the allow-list).
//   - Credentials are required (the session cookie travels), so
//     Access-Control-Allow-Credentials=true is set unconditionally for
//     allowed origins. Browsers reject wildcard + credentials, which is
//     why we never emit "*".
//   - OPTIONS preflight short-circuits with 204 and the same headers.
//   - When AllowedOrigins is empty (dev/local), the middleware is a
//     no-op. Dev runs same-origin on :8080, so no CORS dance is needed.
//
// CSRF stays a separate concern: RequireCSRF gates the actual mutation,
// CORS just unblocks the browser preflight + credential carry.
func (s *Server) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No allow-list configured (dev) → bypass entirely. Browsers
		// won't issue CORS dances against a same-origin request anyway.
		if len(s.AllowedOrigins) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		origin := r.Header.Get("Origin")
		allowed := false
		for _, a := range s.AllowedOrigins {
			if origin == a {
				allowed = true
				break
			}
		}
		if allowed {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			// Vary on Origin so caches don't serve the wrong origin's
			// CORS headers to a different caller.
			h.Add("Vary", "Origin")

			if r.Method == http.MethodOptions {
				// Preflight: declare the methods, headers, and max-age
				// the actual request is allowed to use.
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, "+auth.CSRFHeaderName)
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
