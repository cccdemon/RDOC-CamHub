package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const SessionTTL = 7 * 24 * time.Hour

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
