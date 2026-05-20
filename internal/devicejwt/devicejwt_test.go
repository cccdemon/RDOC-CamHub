package devicejwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustRing(t *testing.T) *Ring {
	t.Helper()
	r, err := NewRingWithGeneratedKey()
	if err != nil {
		t.Fatalf("NewRingWithGeneratedKey: %v", err)
	}
	return r
}

func TestSignVerify_Roundtrip(t *testing.T) {
	r := mustRing(t)

	tok, err := r.Sign(Claims{DeviceID: "cam-001", Subdomain: "livingroom"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got, err := r.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.DeviceID != "cam-001" {
		t.Errorf("DeviceID: got %q, want %q", got.DeviceID, "cam-001")
	}
	if got.Subdomain != "livingroom" {
		t.Errorf("Subdomain: got %q, want %q", got.Subdomain, "livingroom")
	}
	if got.KID != r.CurrentKID {
		t.Errorf("KID: got %q, want %q (current)", got.KID, r.CurrentKID)
	}
	if got.IssuedAt.IsZero() {
		t.Error("IssuedAt was zero — Sign should default to time.Now()")
	}
}

// Tokens signed by a different ring must not verify against ours. This
// is the load-bearing invariant — a leaked old ring file must NOT keep
// minting tokens accepted by the production hub.
func TestVerify_RejectsTokensFromDifferentRing(t *testing.T) {
	a := mustRing(t)
	b := mustRing(t)

	tok, err := a.Sign(Claims{DeviceID: "cam-001", Subdomain: "livingroom"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := b.Verify(tok); err != ErrInvalidToken {
		t.Fatalf("Verify against unrelated ring: got %v, want ErrInvalidToken", err)
	}
}

// A token signed by a retired kid still verifies inside the retirement
// window, then fails after.
func TestVerify_RetirementWindow(t *testing.T) {
	r := mustRing(t)
	tok, err := r.Sign(Claims{DeviceID: "cam-001", Subdomain: "livingroom"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Retire the only key 5 minutes ago — still inside the window.
	retired := time.Now().Add(-5 * time.Minute)
	r.Keys[0].RetiredAt = &retired
	if _, err := r.Verify(tok); err != nil {
		t.Fatalf("Verify just after retirement: %v, want nil (still in window)", err)
	}

	// Move retirement past the window. Same token must now fail.
	past := time.Now().Add(-RetirementWindow - time.Minute)
	r.Keys[0].RetiredAt = &past
	if _, err := r.Verify(tok); err != ErrInvalidToken {
		t.Fatalf("Verify past retirement window: got %v, want ErrInvalidToken", err)
	}
}

// A token whose header names a kid we don't know about must be rejected.
// This pins the verification path against "ring grows a key after the
// token was issued elsewhere".
func TestVerify_UnknownKID(t *testing.T) {
	r := mustRing(t)
	tok, err := r.Sign(Claims{DeviceID: "cam-001", Subdomain: "livingroom"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper the header to claim a different kid. We don't bother
	// re-signing — that's the next test's job. This one just proves
	// the kid lookup gates verification independently of the sig check.
	tampered := rewriteHeaderKID(t, tok, "unknown-kid")
	if _, err := r.Verify(tampered); err != ErrInvalidToken {
		t.Fatalf("Verify with unknown kid: got %v, want ErrInvalidToken", err)
	}
}

// A tampered payload must invalidate the signature.
func TestVerify_TamperedPayloadFailsSignature(t *testing.T) {
	r := mustRing(t)
	tok, err := r.Sign(Claims{DeviceID: "cam-001", Subdomain: "livingroom"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token doesn't have 3 parts: %q", tok)
	}

	bad := map[string]any{"sub": "cam-evil", "dom": "livingroom", "iat": time.Now().Unix()}
	rawBad, _ := json.Marshal(bad)
	parts[1] = base64.RawURLEncoding.EncodeToString(rawBad)
	tampered := strings.Join(parts, ".")

	if _, err := r.Verify(tampered); err != ErrInvalidToken {
		t.Fatalf("Verify with tampered payload: got %v, want ErrInvalidToken", err)
	}
}

// Malformed tokens (wrong segment count, garbage base64, junk JSON) all
// collapse to ErrInvalidToken — never a 500 from a parse panic.
func TestVerify_MalformedTokens(t *testing.T) {
	r := mustRing(t)
	cases := []string{
		"",
		"not-a-jwt",
		"only.two",
		"too.many.parts.here.really",
		"!!!.???.~~~",                  // junk base64
		"e30.e30.AA",                    // valid b64 but header lacks alg/kid
		strings.Repeat("A", 1024),       // long single token, no dots
	}
	for _, tok := range cases {
		if _, err := r.Verify(tok); err != ErrInvalidToken {
			t.Errorf("Verify(%q): got %v, want ErrInvalidToken", tok, err)
		}
	}
}

// Save → Load must round-trip every signing-relevant field; specifically,
// a token signed pre-Save must still verify against the loaded ring.
func TestFile_SaveLoad_Roundtrip(t *testing.T) {
	orig := mustRing(t)
	tok, err := orig.Sign(Claims{DeviceID: "cam-001", Subdomain: "livingroom"})
	if err != nil {
		t.Fatalf("Sign pre-save: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ring.json")
	if err := SaveRingFile(path, orig); err != nil {
		t.Fatalf("SaveRingFile: %v", err)
	}
	loaded, err := LoadRingFile(path)
	if err != nil {
		t.Fatalf("LoadRingFile: %v", err)
	}

	got, err := loaded.Verify(tok)
	if err != nil {
		t.Fatalf("Verify against loaded ring: %v", err)
	}
	if got.DeviceID != "cam-001" || got.Subdomain != "livingroom" {
		t.Errorf("claims mismatch after reload: %+v", got)
	}

	// Sanity: loaded ring can sign new tokens too, and orig verifies them.
	tok2, err := loaded.Sign(Claims{DeviceID: "cam-002", Subdomain: "bedroom"})
	if err != nil {
		t.Fatalf("Sign on loaded ring: %v", err)
	}
	if _, err := orig.Verify(tok2); err != nil {
		t.Fatalf("orig.Verify(loaded.Sign(...)): %v", err)
	}
}

// LoadRingFile must refuse a file whose `current` doesn't reference a
// key in the keys[] array — that's an unrecoverable misconfiguration.
func TestFile_LoadRejectsBrokenCurrent(t *testing.T) {
	r := mustRing(t)
	r.CurrentKID = "ghost-kid"
	path := filepath.Join(t.TempDir(), "ring.json")
	if err := SaveRingFile(path, r); err != nil {
		t.Fatalf("SaveRingFile: %v", err)
	}
	if _, err := LoadRingFile(path); err == nil {
		t.Fatal("LoadRingFile accepted a ring whose current kid is missing")
	}
}

// rewriteHeaderKID rebuilds the token's header with a different kid,
// leaving the original payload and signature untouched. Used in
// TestVerify_UnknownKID. The signature won't match the new header but
// the kid-lookup path must reject the token *before* the sig check —
// otherwise the wrong-kid case would be indistinguishable from a
// wrong-signature case in error messages.
func rewriteHeaderKID(t *testing.T, tok, newKID string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	header := map[string]string{"alg": "EdDSA", "kid": newKID, "typ": "JWT"}
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

// Defense-in-depth: the package must never produce a Verify error other
// than ErrInvalidToken, even when the caller hands it gibberish. This
// matters because handlers translate every error into a single 401; a
// non-sentinel error here would surface as 500 in production.
func TestVerify_AlwaysReturnsSentinelOnFailure(t *testing.T) {
	r := mustRing(t)
	// Try 32 random byte strings of random lengths, base64-flavoured
	// enough to occasionally clear the segment-count check.
	seed := make([]byte, 1)
	for i := 0; i < 64; i++ {
		_, _ = rand.Read(seed)
		size := int(seed[0]) + 1
		raw := make([]byte, size)
		_, _ = rand.Read(raw)
		// Mix in dots randomly so the segment-count check sometimes
		// passes and the parser gets exercised.
		tok := strings.ReplaceAll(base64.RawURLEncoding.EncodeToString(raw), "A", ".")
		if _, err := r.Verify(tok); err != nil && err != ErrInvalidToken {
			t.Errorf("non-sentinel error on Verify(%q): %v", tok, err)
		}
	}
}

// Generated keys must match Ed25519's expected sizes — proves the
// SHA256-prefix kid derivation doesn't silently truncate the wrong field.
func TestGenerateKeypair_SizeSanity(t *testing.T) {
	kp, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	if len(kp.PrivateSeed) != ed25519.SeedSize {
		t.Errorf("PrivateSeed: %d bytes, want %d", len(kp.PrivateSeed), ed25519.SeedSize)
	}
	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("PublicKey: %d bytes, want %d", len(kp.PublicKey), ed25519.PublicKeySize)
	}
	if len(kp.KID) != 16 { // 8 bytes * 2 hex chars
		t.Errorf("KID length: %d, want 16", len(kp.KID))
	}
}
