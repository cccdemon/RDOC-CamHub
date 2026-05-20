package devicejwt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// LoadRingFile reads a ring from disk. The on-disk JSON uses hex-encoded
// private seeds + public keys — chosen over base64 because every
// existing secret in this repo (postgres_password, db_url, session
// material) is hex, and consistency at the secrets/ boundary keeps the
// Makefile's chown/chmod sweep uniform.
func LoadRingFile(path string) (*Ring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	r := &Ring{}
	if err := json.Unmarshal(data, r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// Decode hex columns into the live byte slices.
	for i := range r.Keys {
		k := &r.Keys[i]
		if k.PrivateHex != "" {
			seed, err := hex.DecodeString(k.PrivateHex)
			if err != nil {
				return nil, fmt.Errorf("decode private for kid %q: %w", k.KID, err)
			}
			if len(seed) != ed25519.SeedSize {
				return nil, fmt.Errorf("kid %q: private seed is %d bytes, want %d", k.KID, len(seed), ed25519.SeedSize)
			}
			k.PrivateSeed = seed
		}
		pub, err := hex.DecodeString(k.PublicHex)
		if err != nil {
			return nil, fmt.Errorf("decode public for kid %q: %w", k.KID, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("kid %q: public key is %d bytes, want %d", k.KID, len(pub), ed25519.PublicKeySize)
		}
		k.PublicKey = pub
	}
	if r.CurrentKID == "" {
		return nil, fmt.Errorf("%s: missing `current` kid", path)
	}
	if r.findKey(r.CurrentKID) == nil {
		return nil, fmt.Errorf("%s: current kid %q not in keys[]", path, r.CurrentKID)
	}
	return r, nil
}

// SaveRingFile writes the ring to disk with mode 0600. The file mode is
// belt-and-suspenders alongside the Makefile's `chmod 600 secrets/*` —
// if an operator runs the init outside the Makefile we still don't end
// up with a world-readable signing key.
func SaveRingFile(path string, r *Ring) error {
	// Mirror the byte slices into hex columns for serialisation.
	out := *r
	out.Keys = make([]Keypair, len(r.Keys))
	for i, k := range r.Keys {
		out.Keys[i] = k
		out.Keys[i].PublicHex = hex.EncodeToString(k.PublicKey)
		if len(k.PrivateSeed) > 0 {
			out.Keys[i].PrivateHex = hex.EncodeToString(k.PrivateSeed)
		}
	}

	data, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ring: %w", err)
	}
	// Write atomically: temp file in same dir, then rename. This avoids
	// a half-written file becoming readable on a crash mid-write.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}
