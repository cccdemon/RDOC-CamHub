package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// doRefresh runs the refresh handler with the supplied cookie value (empty
// means no cookie). Mirrors doLogin's IP context shim.
func doRefresh(t *testing.T, srv *Server, sessionCookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", nil)
	if sessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionCookie})
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyIP{}, netip.MustParseAddr("1.2.3.4")))
	rec := httptest.NewRecorder()
	srv.refresh(rec, req)
	return rec
}

// assertClearingCookies verifies the response sets clearing cookies for both
// the session and CSRF cookie names. Any refresh failure path must do this
// so a client with a junked cookie ends up with a clean slate.
func assertClearingCookies(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	cookies := rec.Result().Cookies()
	sawSession, sawCSRF := false, false
	for _, c := range cookies {
		switch c.Name {
		case auth.SessionCookieName:
			sawSession = true
			if c.MaxAge >= 0 {
				t.Errorf("session cookie not cleared: MaxAge=%d (want negative)", c.MaxAge)
			}
		case auth.CSRFCookieName:
			sawCSRF = true
			if c.MaxAge >= 0 {
				t.Errorf("csrf cookie not cleared: MaxAge=%d (want negative)", c.MaxAge)
			}
		}
	}
	if !sawSession {
		t.Error("response missing clearing session cookie")
	}
	if !sawCSRF {
		t.Error("response missing clearing csrf cookie")
	}
}

func TestRefresh_NoCookie_Returns401_AndClearsCookies(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})

	rec := doRefresh(t, srv, "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	assertClearingCookies(t, rec)
}

func TestRefresh_UnknownSession_Returns401_AndClearsCookies(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{active: map[string]*db.SessionWithUser{}})

	rec := doRefresh(t, srv, "no-such-session")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	assertClearingCookies(t, rec)
}

// Pins the "beyond refresh window" failure mode: the real db.Rotate
// returns ErrNotFound for both unknown and out-of-window sessions, so the
// handler must surface the same 401 + cleared cookies regardless of which.
func TestRefresh_BeyondRefreshWindow_LooksIdenticalToUnknown(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{
		rotateErr: db.ErrNotFound,
		active: map[string]*db.SessionWithUser{
			"old-id": {Session: db.Session{ID: "old-id"}},
		},
	})

	rec := doRefresh(t, srv, "old-id")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	assertClearingCookies(t, rec)
}

func TestRefresh_DBError_Returns500(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{
		rotateErr: errors.New("postgres exploded"),
		active: map[string]*db.SessionWithUser{
			"old-id": {Session: db.Session{ID: "old-id"}},
		},
	})

	rec := doRefresh(t, srv, "old-id")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
}

func TestRefresh_Valid_RotatesIDAndIssuesFreshCookies(t *testing.T) {
	oldID := "old-session-id"
	sessions := &stubSessions{
		active: map[string]*db.SessionWithUser{
			oldID: {
				Session:   db.Session{ID: oldID, UserID: 42, CreatedAt: time.Now().Add(-2 * time.Minute)},
				UserEmail: "user@example.org",
				UserRole:  db.RoleOperator,
			},
		},
	}
	srv := newTestServer(t, &stubUsers{}, sessions)

	rec := doRefresh(t, srv, oldID)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204 (body=%q)", rec.Code, rec.Body.String())
	}
	if sessions.rotated != 1 {
		t.Fatalf("Rotate was called %d times, want 1", sessions.rotated)
	}

	// Old id must be gone from the active map (invalidated).
	if _, ok := sessions.active[oldID]; ok {
		t.Fatal("old session id still active after refresh — must be invalidated")
	}

	// A new session+csrf cookie must be set; the session cookie value must
	// differ from the old id.
	var (
		newSessionVal string
		csrfPresent   bool
	)
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case auth.SessionCookieName:
			if c.MaxAge < 0 {
				t.Error("session cookie unexpectedly cleared")
			}
			newSessionVal = c.Value
		case auth.CSRFCookieName:
			if c.MaxAge < 0 {
				t.Error("csrf cookie unexpectedly cleared")
			}
			csrfPresent = true
		}
	}
	if newSessionVal == "" {
		t.Fatal("no session cookie set on successful refresh")
	}
	if newSessionVal == oldID {
		t.Fatal("session cookie value unchanged after refresh — must rotate")
	}
	if !csrfPresent {
		t.Fatal("no csrf cookie set on successful refresh")
	}
	if _, ok := sessions.active[newSessionVal]; !ok {
		t.Fatal("new session id not registered in active map")
	}
}

// Cookie TTL pin. PR-S5 deliberately shortens the cookie's lifetime from
// the old 7d SessionTTL to SessionAccessTTL (15 min). The Expires attribute
// drives browser-side eviction, so regressing this would silently re-enable
// long-lived cookies without anyone noticing.
func TestSessionCookie_ExpiresMatchesSessionAccessTTL(t *testing.T) {
	cfg := SessionCookieConfig{Secure: true}
	before := time.Now()
	c := cfg.NewSession("abc")
	after := time.Now()

	// Allow a small clock window: Expires must fall within
	// [before+TTL, after+TTL]. Beyond that, the constant doesn't match.
	want := auth.SessionAccessTTL
	lo := before.Add(want - 2*time.Second)
	hi := after.Add(want + 2*time.Second)
	if c.Expires.Before(lo) || c.Expires.After(hi) {
		t.Fatalf("session cookie Expires=%v outside [%v, %v] (TTL=%v)",
			c.Expires, lo, hi, want)
	}
}

func TestCSRFCookie_ExpiresMatchesSessionAccessTTL(t *testing.T) {
	cfg := SessionCookieConfig{Secure: true}
	before := time.Now()
	c := cfg.NewCSRF("abc")
	after := time.Now()

	want := auth.SessionAccessTTL
	lo := before.Add(want - 2*time.Second)
	hi := after.Add(want + 2*time.Second)
	if c.Expires.Before(lo) || c.Expires.After(hi) {
		t.Fatalf("csrf cookie Expires=%v outside [%v, %v] (TTL=%v)",
			c.Expires, lo, hi, want)
	}
}
