package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Two-tier session lifecycle (PR-S5, Plan §15 Q9 resolution).
//
//   SessionAccessTTL — server-side validity of a single session id. After
//     this elapses without a successful POST /v1/auth/refresh, the row's
//     expires_at is in the past and RequireSession returns 401. The cookie
//     itself is also set with Max-Age = SessionAccessTTL: after 15 min of
//     idle the browser stops sending it, so the UI must call /refresh
//     proactively to roll the session forward.
//
//   SessionRefreshWindow — hard cap measured from the original login
//     (sessions.created_at). Refresh is allowed only while
//     created_at + SessionRefreshWindow > now(); beyond that the user must
//     re-authenticate even if the cookie is still present.
const (
	SessionAccessTTL     = 15 * time.Minute
	SessionRefreshWindow = 7 * 24 * time.Hour
)

const (
	SessionCookieName = "camhub_session"
	CSRFCookieName    = "camhub_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
)

// NewSessionID returns a 32-byte random hex string.
func NewSessionID() (string, error) { return randomHex(32) }

// NewCSRFToken returns a 32-byte random hex string suitable as a CSRF
// double-submit value. Independent of the session ID so neither leaks
// information about the other.
func NewCSRFToken() (string, error) { return randomHex(32) }

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
