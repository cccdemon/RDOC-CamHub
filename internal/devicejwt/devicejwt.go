// Package devicejwt issues and verifies the long-lived bearer tokens
// CamHub hands to a cam at enrollment (Plan §4.1) and the cam echoes back
// on every heartbeat (§4.2).
//
// Design choices:
//
//   - Ed25519, not HMAC. The hub is the only signer, and the cam-side
//     verifier doesn't need the symmetric secret — that secret never has
//     to leave the hub's secrets/ mount.
//   - Hand-rolled JWT, not golang-jwt/jwt. The token shape is fixed and
//     the verification rules are unusual enough (no `exp`, retirement
//     window on kid) that the library's hooks would obscure them.
//   - No `exp` claim, by design. Rotation is via kid (§4.3): keys move
//     from current → retired → forbidden, with a 30-day acceptance
//     window after retirement during which old tokens still verify.
//   - File-backed key ring with a forward-compatible JSON schema. M1.B
//     ships a ring-of-one; M4 hardening can add a `rotate` subcommand
//     that appends a new key and marks the old one Retired without
//     changing the file format.
package devicejwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RetirementWindow is how long a kid stays acceptable for verification
// after it has been retired (Plan §4.3). Tokens older than this fail
// even if the device still holds them — cam must re-enroll.
const RetirementWindow = 30 * 24 * time.Hour

// Claims is the minimal payload — everything the device JWT carries.
// Plan §4.1: hub signs {device_id, assigned_subdomain, iat, kid}.
type Claims struct {
	DeviceID  string    `json:"sub"` // standard JWT sub claim
	Subdomain string    `json:"dom"`
	IssuedAt  time.Time `json:"-"` // serialised as `iat` int64

	// KID is set on Verify; ignored on Sign (the ring's current kid is
	// used). Exposed so handlers can detect tokens signed by retiring
	// keys and warn the cam to re-enroll.
	KID string `json:"-"`
}

// Keypair holds one signing identity. PrivateSeed is nil for retired
// keys (verification-only). The seed is the 32-byte ed25519 seed, not
// the 64-byte expanded private key — saves half the on-disk footprint
// and is the canonical representation.
type Keypair struct {
	KID         string     `json:"kid"`
	PrivateSeed []byte     `json:"-"`         // populated only for active signers
	PrivateHex  string     `json:"private,omitempty"`
	PublicKey   []byte     `json:"-"`
	PublicHex   string     `json:"public"`
	CreatedAt   time.Time  `json:"created_at"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
}

// Ring is the in-memory view of the signing-key file. CurrentKID names
// the keypair used for new Sign calls; every keypair (current + retired)
// is consulted on Verify, with retirement enforced via RetirementWindow.
type Ring struct {
	Keys       []Keypair `json:"keys"`
	CurrentKID string    `json:"current"`
}

// SigningKID returns the kid the ring will use for the next Sign call.
// Exposed for callers that need to record which key was used (e.g. the
// devices.device_jwt_kid column for retirement targeting in M4).
//
// Named SigningKID rather than the obvious "CurrentKID" because the
// struct field is already called CurrentKID and a Go type can't have a
// method and a field with the same name. The field stays exported
// because the JSON marshaller needs it; this method is the caller-
// facing accessor.
func (r *Ring) SigningKID() string { return r.CurrentKID }

// NewRingWithGeneratedKey builds a ring-of-one with a freshly generated
// Ed25519 keypair. Used by the `devicejwt init` CLI; tests use it
// directly to avoid touching disk.
func NewRingWithGeneratedKey() (*Ring, error) {
	kp, err := generateKeypair()
	if err != nil {
		return nil, err
	}
	return &Ring{
		Keys:       []Keypair{*kp},
		CurrentKID: kp.KID,
	}, nil
}

// Sign produces a JWT for the given claims using the ring's current key.
// The IssuedAt is set to time.Now if zero.
func (r *Ring) Sign(c Claims) (string, error) {
	signer, err := r.current()
	if err != nil {
		return "", err
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = time.Now()
	}

	header := map[string]string{
		"alg": "EdDSA",
		"kid": signer.KID,
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	payload := claimsWire{
		Sub: c.DeviceID,
		Dom: c.Subdomain,
		Iat: c.IssuedAt.Unix(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	signingInput := b64(headerJSON) + "." + b64(payloadJSON)
	if len(signer.PrivateSeed) != ed25519.SeedSize {
		return "", errors.New("devicejwt: current key has no private seed")
	}
	priv := ed25519.NewKeyFromSeed(signer.PrivateSeed)
	sig := ed25519.Sign(priv, []byte(signingInput))

	return signingInput + "." + b64(sig), nil
}

// Verify parses the token, locates the named kid in the ring, enforces
// the retirement window, and checks the signature. Returns the claims
// on success.
//
// All failure modes return ErrInvalidToken so callers can collapse them
// into a single 401 without leaking which check failed.
func (r *Ring) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, ErrInvalidToken
	}
	if hdr.Alg != "EdDSA" || hdr.KID == "" {
		return nil, ErrInvalidToken
	}

	kp := r.findKey(hdr.KID)
	if kp == nil {
		return nil, ErrInvalidToken
	}
	if kp.RetiredAt != nil && time.Since(*kp.RetiredAt) > RetirementWindow {
		return nil, ErrInvalidToken
	}
	if len(kp.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidToken
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(kp.PublicKey, []byte(signingInput), sig) {
		return nil, ErrInvalidToken
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var p claimsWire
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return nil, ErrInvalidToken
	}
	if p.Sub == "" || p.Dom == "" {
		return nil, ErrInvalidToken
	}

	return &Claims{
		DeviceID:  p.Sub,
		Subdomain: p.Dom,
		IssuedAt:  time.Unix(p.Iat, 0),
		KID:       hdr.KID,
	}, nil
}

// ErrInvalidToken is returned for every Verify failure path. Callers
// SHOULD NOT differentiate causes when responding to the client.
var ErrInvalidToken = errors.New("devicejwt: invalid token")

// claimsWire is the on-the-wire payload shape. We keep IssuedAt as int64
// here to match the JWT convention (`iat` is seconds since epoch).
type claimsWire struct {
	Sub string `json:"sub"`
	Dom string `json:"dom"`
	Iat int64  `json:"iat"`
}

func (r *Ring) current() (*Keypair, error) {
	if r.CurrentKID == "" {
		return nil, errors.New("devicejwt: ring has no current kid")
	}
	kp := r.findKey(r.CurrentKID)
	if kp == nil {
		return nil, fmt.Errorf("devicejwt: current kid %q missing from ring", r.CurrentKID)
	}
	if len(kp.PrivateSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("devicejwt: current kid %q has no private seed", r.CurrentKID)
	}
	return kp, nil
}

func (r *Ring) findKey(kid string) *Keypair {
	for i := range r.Keys {
		if r.Keys[i].KID == kid {
			return &r.Keys[i]
		}
	}
	return nil
}

func generateKeypair() (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519: %w", err)
	}
	seed := priv.Seed()
	// Kid derived from the public key so a key's identity is intrinsic
	// to its material — no PRNG-from-time, no kid collisions on rapid
	// successive `rotate` calls. First 16 hex chars (8 bytes) gives an
	// astronomical collision floor while staying compact in JWT headers.
	sum := sha256.Sum256(pub)
	kid := hex.EncodeToString(sum[:8])
	return &Keypair{
		KID:         kid,
		PrivateSeed: seed,
		PublicKey:   pub,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// b64 is RFC 7515 base64url-without-padding, the JWT encoding.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
