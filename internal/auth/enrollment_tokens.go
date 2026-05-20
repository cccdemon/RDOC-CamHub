package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// EnrollmentTokenLen is the raw byte length of an enrollment token's
// random material (Plan §4.1: "random 32-byte URL-safe string"). The
// emitted token is base64.RawURLEncoding of those 32 bytes — 43 chars,
// no padding, no escaping needed in shell or .env.
const EnrollmentTokenLen = 32

// NewEnrollmentToken mints a fresh single-use enrollment token. Returns
// the raw token (handed to the admin once, never persisted) and its
// SHA-256 hex hash (what the DB stores).
//
// Why SHA-256 and not Argon2id like passwords: enrollment tokens are
// 256-bit cryptographic randoms with no human-chosen material — there
// is nothing to brute-force, and Argon2id would make every register
// lookup require an O(n) scan + slow-verify since you can't index a
// salted hash. SHA-256 of high-entropy input is one-way for any
// realistic attacker who doesn't already have the raw token.
func NewEnrollmentToken() (raw, hash string, err error) {
	b := make([]byte, EnrollmentTokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("read random: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = HashEnrollmentToken(raw)
	return raw, hash, nil
}

// HashEnrollmentToken is the SHA-256 of the raw token, hex-encoded.
// Exposed so the register handler can hash an incoming Bearer token
// and look it up against enrollment_tokens.hash in a single indexed
// SELECT.
func HashEnrollmentToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
