package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// Limits the login request body to keep an attacker from forcing Argon2id to
// run on multi-MB junk. 4 KiB is far above any legitimate {email, password}.
const loginMaxBody = 4 << 10

// Pre-Argon2 length caps. Email follows RFC 5321's 320-char limit; the
// password cap is set generously so legitimate passphrases still pass but
// a 1 MB "password" cannot reach the hashing function.
const (
	maxEmailLen    = 320
	maxPasswordLen = 1024
)

// Reused for the "unknown email" branch so login timing doesn't disclose
// whether an account exists.
const dummyArgon2Hash = "$argon2id$v=19$m=65536,t=2,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, loginMaxBody)

	var req loginReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "login body exceeds size limit")
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "email and password required")
		return
	}
	if len(req.Email) > maxEmailLen || len(req.Password) > maxPasswordLen {
		// Reject before we spend Argon2id cost on attacker-controlled input.
		writeError(w, http.StatusBadRequest, "bad_request", "email or password exceeds length limit")
		return
	}

	user, err := s.Users.ByEmail(r.Context(), req.Email)
	if errors.Is(err, db.ErrNotFound) {
		_ = auth.VerifyPassword(req.Password, dummyArgon2Hash)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password incorrect")
		return
	}
	if err != nil {
		s.Logger.Error("login: lookup user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "lookup failed")
		return
	}

	if err := auth.VerifyPassword(req.Password, user.PasswordHash); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password incorrect")
		return
	}

	sid, err := auth.NewSessionID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "session create failed")
		return
	}
	csrf, err := auth.NewCSRFToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "csrf create failed")
		return
	}
	ip := ClientIP(r.Context())
	if err := s.Sessions.Create(r.Context(), sid, user.ID, auth.SessionTTL, r.UserAgent(), ip); err != nil {
		s.Logger.Error("login: create session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "session create failed")
		return
	}

	http.SetCookie(w, s.Cookies.NewSession(sid))
	http.SetCookie(w, s.Cookies.NewCSRF(csrf))
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(auth.SessionCookieName)
	if err == nil && c.Value != "" {
		if err := s.Sessions.Delete(r.Context(), c.Value); err != nil {
			s.Logger.Warn("logout: delete session", "err", err)
		}
	}
	http.SetCookie(w, s.Cookies.NewClearing(auth.SessionCookieName))
	http.SetCookie(w, s.Cookies.NewClearingCSRF())
	w.WriteHeader(http.StatusNoContent)
}

// me returns the current Principal. Mounted under the authenticated group,
// so RequireSession has already validated the cookie and attached the
// principal — this handler trusts that and never touches the DB itself.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "no session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": p.UserID,
		"email":   p.Email,
		"role":    p.Role,
	})
}
