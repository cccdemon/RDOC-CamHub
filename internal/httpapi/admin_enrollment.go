package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// EnrollmentTokenWriter is the slice of *db.EnrollmentTokenStore the
// HTTP layer depends on. Interface (rather than the concrete pointer)
// so handler tests can stub it without touching Postgres.
//
// Create mints a new token (admin endpoint + CLI).
// Consume atomically marks a token used by a given device id (the
// device-register handler in M1.E).
type EnrollmentTokenWriter interface {
	Create(ctx context.Context, hash string, createdBy int64, ttl time.Duration, note string) (*db.EnrollmentToken, error)
	Consume(ctx context.Context, hash, deviceID string) error
}

// enrollmentTokensMaxBody caps the admin-only POST body. The legitimate
// shape is tiny (ttl_hours + note); 4 KiB is the same cap login uses.
const enrollmentTokensMaxBody = 4 << 10

// maxNoteLen pins the audit-note length so a careless admin can't write
// kilobytes of free-form into the DB. 512 chars is comfortable for "garage
// cam, ordered 2026-05-20, shipped via …" without becoming a payload vector.
const maxNoteLen = 512

// defaultEnrollmentTTL is the Plan §4.1 default — 24 h. Admins can shorten
// it via ttl_hours; we cap at 168 h (7 days) so a forgotten token can't
// hang around indefinitely.
const (
	defaultEnrollmentTTL = 24 * time.Hour
	maxEnrollmentTTL     = 7 * 24 * time.Hour
)

type mintEnrollmentReq struct {
	// TTLHours overrides defaultEnrollmentTTL. Float so an admin can
	// pass 0.5 for a 30-min token during a tight enrollment window.
	TTLHours *float64 `json:"ttl_hours,omitempty"`
	Note     string   `json:"note,omitempty"`
}

type mintEnrollmentResp struct {
	// Token is the raw secret — shown once. The DB stores only the
	// SHA-256 hash so a later breach can't replay this.
	Token     string    `json:"token"`
	ID        int64     `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedBy int64     `json:"created_by"`
}

// mintEnrollmentToken handles POST /v1/admin/enrollment-tokens. Wired
// into the admin group (RequireSession + RequireRole(admin) +
// RequireCSRF — same chain as every other admin endpoint). The token
// secret is returned ONCE in the response; subsequent reads can only
// see the row metadata (id, expires_at, consumed_at).
func (s *Server) mintEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, enrollmentTokensMaxBody)

	// The admin group's middleware guarantees a Principal in context;
	// a missing one is a programmer error (handler mounted in the wrong
	// group) — treat as 401 rather than crash.
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "no session")
		return
	}

	var req mintEnrollmentReq
	if r.ContentLength > 0 || r.Header.Get("Content-Type") != "" {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds size limit")
				return
			}
			writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
			return
		}
	}

	ttl := defaultEnrollmentTTL
	if req.TTLHours != nil {
		if *req.TTLHours <= 0 {
			writeError(w, http.StatusBadRequest, "bad_request", "ttl_hours must be > 0")
			return
		}
		// Floats let admins pass 0.5; we still cap at the max above to
		// prevent month-long enrollment windows.
		candidate := time.Duration(*req.TTLHours * float64(time.Hour))
		if candidate > maxEnrollmentTTL {
			writeError(w, http.StatusBadRequest, "bad_request", "ttl_hours exceeds 168 (7-day) cap")
			return
		}
		ttl = candidate
	}

	if len(req.Note) > maxNoteLen {
		writeError(w, http.StatusBadRequest, "bad_request", "note exceeds length limit")
		return
	}

	raw, hash, err := auth.NewEnrollmentToken()
	if err != nil {
		s.Logger.Error("enrollment: mint token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "mint failed")
		return
	}

	t, err := s.EnrollmentTokens.Create(r.Context(), hash, p.UserID, ttl, req.Note)
	if err != nil {
		s.Logger.Error("enrollment: persist token", "err", err, "actor", p.UserID)
		writeError(w, http.StatusInternalServerError, "internal", "persist failed")
		return
	}

	writeJSON(w, http.StatusCreated, mintEnrollmentResp{
		Token:     raw,
		ID:        t.ID,
		ExpiresAt: t.ExpiresAt,
		CreatedBy: t.CreatedBy,
	})
}
