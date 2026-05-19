package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

func newCSRFServer(t *testing.T, allowed ...string) *Server {
	t.Helper()
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})
	srv.AllowedOrigins = allowed
	return srv
}

// reachedHandler returns a handler that records it was invoked.
func reachedHandler() (*terminalHandler, http.Handler) {
	t := &terminalHandler{}
	return t, t
}

func TestRequireCSRF_SafeMethods_NoTokenRequired(t *testing.T) {
	srv := newCSRFServer(t)
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(m, func(t *testing.T) {
			term, h := reachedHandler()
			req := httptest.NewRequest(m, "/protected", nil)
			rec := httptest.NewRecorder()
			srv.RequireCSRF(h).ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status %d, want 200", m, rec.Code)
			}
			if !term.called {
				t.Fatalf("%s: downstream must run for safe method", m)
			}
		})
	}
}

func TestRequireCSRF_BearerAuth_Bypasses(t *testing.T) {
	srv := newCSRFServer(t)
	term, h := reachedHandler()

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.Header.Set("Authorization", "Bearer rdoc_pat_dummy")
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (Bearer should bypass CSRF)", rec.Code)
	}
	if !term.called {
		t.Fatal("downstream must run for Bearer-authenticated request")
	}
}

func TestRequireCSRF_MissingCookie_Returns403(t *testing.T) {
	srv := newCSRFServer(t)
	term, h := reachedHandler()

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.Header.Set(auth.CSRFHeaderName, "anything")
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if term.called {
		t.Fatal("downstream must not run when cookie missing")
	}
}

func TestRequireCSRF_MissingHeader_Returns403(t *testing.T) {
	srv := newCSRFServer(t)
	term, h := reachedHandler()

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "abc123"})
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if term.called {
		t.Fatal("downstream must not run when header missing")
	}
}

func TestRequireCSRF_Mismatch_Returns403(t *testing.T) {
	srv := newCSRFServer(t)
	term, h := reachedHandler()

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "cookie-value"})
	req.Header.Set(auth.CSRFHeaderName, "different-value")
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if term.called {
		t.Fatal("downstream must not run on token mismatch")
	}
}

func TestRequireCSRF_Match_Passes(t *testing.T) {
	srv := newCSRFServer(t)
	term, h := reachedHandler()

	const tok = "matching-token-12345"
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: tok})
	req.Header.Set(auth.CSRFHeaderName, tok)
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if !term.called {
		t.Fatal("downstream must run on valid CSRF pair")
	}
}

func TestRequireCSRF_EmptyAllowedOrigins_SkipsOriginCheck(t *testing.T) {
	srv := newCSRFServer(t) // no allowed origins
	term, h := reachedHandler()

	const tok = "ok"
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: tok})
	req.Header.Set(auth.CSRFHeaderName, tok)
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (origin check disabled by empty list)", rec.Code)
	}
	if !term.called {
		t.Fatal("downstream must run when origin check is disabled")
	}
}

func TestRequireCSRF_AllowedOrigins_BlocksMismatchedOrigin(t *testing.T) {
	srv := newCSRFServer(t, "https://app.raumdock.org")
	term, h := reachedHandler()

	const tok = "ok"
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: tok})
	req.Header.Set(auth.CSRFHeaderName, tok)
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if term.called {
		t.Fatal("downstream must not run for disallowed origin")
	}
}

func TestRequireCSRF_AllowedOrigins_PermitsMatchingOrigin(t *testing.T) {
	srv := newCSRFServer(t, "https://app.raumdock.org")
	term, h := reachedHandler()

	const tok = "ok"
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.Header.Set("Origin", "https://app.raumdock.org")
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: tok})
	req.Header.Set(auth.CSRFHeaderName, tok)
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !term.called {
		t.Fatal("downstream must run on matching origin")
	}
}

func TestRequireCSRF_AllowedOrigins_FallsBackToReferer(t *testing.T) {
	srv := newCSRFServer(t, "https://app.raumdock.org")
	term, h := reachedHandler()

	const tok = "ok"
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	// No Origin header. Caddy / older browsers may strip it; Referer is fallback.
	req.Header.Set("Referer", "https://app.raumdock.org/some/path")
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: tok})
	req.Header.Set(auth.CSRFHeaderName, tok)
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (Referer fallback)", rec.Code)
	}
	if !term.called {
		t.Fatal("downstream must run when Referer is the only origin signal and matches")
	}
}

func TestRequireCSRF_AllowedOrigins_NoOriginOrRefererBlocks(t *testing.T) {
	srv := newCSRFServer(t, "https://app.raumdock.org")
	term, h := reachedHandler()

	const tok = "ok"
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: tok})
	req.Header.Set(auth.CSRFHeaderName, tok)
	rec := httptest.NewRecorder()
	srv.RequireCSRF(h).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if term.called {
		t.Fatal("downstream must not run when neither Origin nor Referer is provided and an allow-list is configured")
	}
}

// Login response shape: ensures the camhub_csrf cookie ships alongside the
// session cookie on a successful login. This is the bootstrap moment for the
// double-submit dance.
func TestLogin_SetsBothSessionAndCSRFCookies(t *testing.T) {
	hash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	users := &stubUsers{users: map[string]*db.User{
		"known@example.org": {ID: 1, Email: "known@example.org", PasswordHash: hash, Role: db.RoleAdmin},
	}}
	srv := newTestServer(t, users, &stubSessions{})

	rec := doLogin(t, srv, []byte(`{"email":"known@example.org","password":"correct-horse-battery-staple"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("login status: got %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}

	var sawSession, sawCSRF bool
	var csrfHttpOnly bool
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case auth.SessionCookieName:
			sawSession = true
			if !c.HttpOnly {
				t.Fatal("session cookie must be HttpOnly")
			}
		case auth.CSRFCookieName:
			sawCSRF = true
			csrfHttpOnly = c.HttpOnly
			if c.Value == "" {
				t.Fatal("csrf cookie value must be non-empty")
			}
		}
	}
	if !sawSession {
		t.Fatal("login response did not set the session cookie")
	}
	if !sawCSRF {
		t.Fatal("login response did not set the csrf cookie")
	}
	if csrfHttpOnly {
		t.Fatal("csrf cookie must NOT be HttpOnly (JS has to read it)")
	}
}
