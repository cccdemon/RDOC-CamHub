package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// stubEnrollmentTokens records the last Create / Consume call and lets a
// test substitute a canned response or error. The handler never reads
// back what it wrote on the Create path, so we don't need to model the
// full store. Consume tracks (hash, deviceID) for M1.E-style tests.
type stubEnrollmentTokens struct {
	// Create side
	lastHash      string
	lastCreatedBy int64
	lastTTL       time.Duration
	lastNote      string
	resp          *db.EnrollmentToken
	err           error

	// Consume side
	consumedHash     string
	consumedDeviceID string
	consumeErr       error
}

func (s *stubEnrollmentTokens) Create(_ context.Context, hash string, createdBy int64, ttl time.Duration, note string) (*db.EnrollmentToken, error) {
	s.lastHash = hash
	s.lastCreatedBy = createdBy
	s.lastTTL = ttl
	s.lastNote = note
	if s.err != nil {
		return nil, s.err
	}
	if s.resp != nil {
		return s.resp, nil
	}
	// Default: minimal valid response so happy-path tests don't have to
	// pre-populate the stub.
	return &db.EnrollmentToken{
		ID:        42,
		Hash:      hash,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
		Note:      note,
	}, nil
}

func (s *stubEnrollmentTokens) Consume(_ context.Context, hash, deviceID string) error {
	s.consumedHash = hash
	s.consumedDeviceID = deviceID
	return s.consumeErr
}

// adminTestServer is the minimal Server wiring the admin-enrollment
// handler needs: a stub enrollment store and a logger that goes nowhere.
// Session/CSRF middleware isn't exercised here — we drive the handler
// function directly and inject a Principal manually.
func adminTestServer(t *testing.T, store *stubEnrollmentTokens) *Server {
	t.Helper()
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})
	srv.EnrollmentTokens = store
	return srv
}

// withAdminPrincipal returns r with an admin Principal attached, so the
// handler's PrincipalFrom lookup returns a usable actor.
func withAdminPrincipal(r *http.Request) *http.Request {
	return r.WithContext(withPrincipal(r.Context(), Principal{
		UserID: 1,
		Email:  "admin@example.org",
		Role:   db.RoleAdmin,
	}))
}

func TestMintEnrollment_DefaultsTo24h(t *testing.T) {
	store := &stubEnrollmentTokens{}
	srv := adminTestServer(t, store)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminPrincipal(req)

	rec := httptest.NewRecorder()
	srv.mintEnrollmentToken(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201 (body=%q)", rec.Code, rec.Body.String())
	}
	if store.lastTTL != 24*time.Hour {
		t.Errorf("default TTL: got %v, want 24h", store.lastTTL)
	}
	if store.lastCreatedBy != 1 {
		t.Errorf("created_by: got %d, want 1 (the admin Principal)", store.lastCreatedBy)
	}
	if store.lastHash == "" {
		t.Error("hash was empty — token must be SHA-256-hashed before persistence")
	}
	if len(store.lastHash) != 64 {
		t.Errorf("hash length: got %d, want 64 (SHA-256 hex)", len(store.lastHash))
	}
}

// Body is the raw token; the stored hash must equal HashEnrollmentToken
// of that raw token. This pins the contract that the cam-side
// /v1/devices/register handler can verify a Bearer token by hashing it
// and matching against enrollment_tokens.hash directly.
func TestMintEnrollment_TokenHashMatchesReturnedSecret(t *testing.T) {
	store := &stubEnrollmentTokens{}
	srv := adminTestServer(t, store)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminPrincipal(req)

	rec := httptest.NewRecorder()
	srv.mintEnrollmentToken(rec, req)

	var resp mintEnrollmentResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, rec.Body.String())
	}
	if resp.Token == "" {
		t.Fatal("response.token was empty — admin needs the secret to hand to a cam")
	}
	if got := auth.HashEnrollmentToken(resp.Token); got != store.lastHash {
		t.Fatalf("hash mismatch:\n persisted=%s\n recomputed=%s", store.lastHash, got)
	}
}

func TestMintEnrollment_CustomTTL_FractionalHours(t *testing.T) {
	store := &stubEnrollmentTokens{}
	srv := adminTestServer(t, store)

	body := []byte(`{"ttl_hours": 0.5}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminPrincipal(req)

	rec := httptest.NewRecorder()
	srv.mintEnrollmentToken(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201", rec.Code)
	}
	if store.lastTTL != 30*time.Minute {
		t.Errorf("TTL: got %v, want 30m", store.lastTTL)
	}
}

func TestMintEnrollment_TTLExceedingCap_Rejected(t *testing.T) {
	store := &stubEnrollmentTokens{}
	srv := adminTestServer(t, store)

	body := []byte(`{"ttl_hours": 200}`) // > 168h cap
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminPrincipal(req)

	rec := httptest.NewRecorder()
	srv.mintEnrollmentToken(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
	if store.lastHash != "" {
		t.Errorf("store called with hash=%q; oversize TTL must reject before persistence", store.lastHash)
	}
}

func TestMintEnrollment_TTLZeroOrNegative_Rejected(t *testing.T) {
	for _, body := range []string{
		`{"ttl_hours": 0}`,
		`{"ttl_hours": -1}`,
	} {
		t.Run(body, func(t *testing.T) {
			store := &stubEnrollmentTokens{}
			srv := adminTestServer(t, store)

			req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader([]byte(body)))
			req.Header.Set("Content-Type", "application/json")
			req = withAdminPrincipal(req)

			rec := httptest.NewRecorder()
			srv.mintEnrollmentToken(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status: got %d, want 400", rec.Code)
			}
		})
	}
}

func TestMintEnrollment_NoteTooLong_Rejected(t *testing.T) {
	store := &stubEnrollmentTokens{}
	srv := adminTestServer(t, store)

	long := strings.Repeat("x", maxNoteLen+1)
	body := []byte(`{"note":"` + long + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminPrincipal(req)

	rec := httptest.NewRecorder()
	srv.mintEnrollmentToken(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

func TestMintEnrollment_NoBody_OK(t *testing.T) {
	// chi.Group's RequireCSRF + RequireSession aren't on the path when we
	// call the handler directly; the only thing the handler reads off
	// the wire is the (possibly empty) body. An empty body means "all
	// defaults" and should succeed.
	store := &stubEnrollmentTokens{}
	srv := adminTestServer(t, store)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", http.NoBody)
	req = withAdminPrincipal(req)

	rec := httptest.NewRecorder()
	srv.mintEnrollmentToken(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201", rec.Code)
	}
	if store.lastTTL != 24*time.Hour {
		t.Errorf("default TTL: got %v, want 24h", store.lastTTL)
	}
}

func TestMintEnrollment_BodyTooLarge_413(t *testing.T) {
	store := &stubEnrollmentTokens{}
	srv := adminTestServer(t, store)

	junk := strings.Repeat("x", 5*1024) // > 4 KiB cap
	body := []byte(`{"note":"` + junk + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminPrincipal(req)

	rec := httptest.NewRecorder()
	srv.mintEnrollmentToken(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: got %d, want 413", rec.Code)
	}
	if store.lastHash != "" {
		t.Error("store was called despite 413")
	}
}

func TestMintEnrollment_DBError_500(t *testing.T) {
	store := &stubEnrollmentTokens{err: errors.New("postgres exploded")}
	srv := adminTestServer(t, store)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminPrincipal(req)

	rec := httptest.NewRecorder()
	srv.mintEnrollmentToken(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
}

func TestMintEnrollment_NoPrincipal_401(t *testing.T) {
	// Programmer-error path: handler mounted without RequireSession.
	// Must not crash; must not write a token.
	store := &stubEnrollmentTokens{}
	srv := adminTestServer(t, store)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	// no withAdminPrincipal — context has no Principal

	rec := httptest.NewRecorder()
	srv.mintEnrollmentToken(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if store.lastHash != "" {
		t.Error("store was called with no principal in context")
	}
}
