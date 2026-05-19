package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const SessionTTL = 7 * 24 * time.Hour
const SessionCookieName = "camhub_session"

// NewSessionID returns a 32-byte random hex string.
func NewSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
