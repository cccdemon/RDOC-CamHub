package httpapi

import (
	"errors"
	"net/http"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// RequireSession reads the session cookie, validates it against the store,
// and attaches a Principal to the request context. Missing / unknown /
// expired sessions all collapse into a single 401 to avoid telegraphing
// state to attackers.
//
// Returns 500 only on infrastructure failure (DB error other than NotFound).
func (s *Server) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.SessionCookieName)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "no session")
			return
		}
		swu, err := s.Sessions.GetActiveWithUser(r.Context(), c.Value)
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "no session")
			return
		}
		if err != nil {
			s.Logger.Error("require_session: lookup", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "session lookup failed")
			return
		}
		p := Principal{
			UserID:    swu.UserID,
			Email:     swu.UserEmail,
			Role:      swu.UserRole,
			SessionID: swu.ID,
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

// RequireRole gates a handler chain on the principal's role. Any-of
// semantics: RequireRole(admin, operator) admits both. Must be composed
// AFTER RequireSession; without a Principal in context it returns 401.
func RequireRole(roles ...db.Role) func(http.Handler) http.Handler {
	allow := make(map[db.Role]struct{}, len(roles))
	for _, r := range roles {
		allow[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				// Programmer error: this middleware was mounted without
				// RequireSession upstream. Treat as auth failure rather
				// than crashing.
				writeError(w, http.StatusUnauthorized, "unauthorized", "no session")
				return
			}
			if _, ok := allow[p.Role]; !ok {
				writeError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
