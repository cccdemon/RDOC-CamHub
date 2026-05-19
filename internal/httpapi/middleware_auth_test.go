package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// terminalHandler captures whether the chain reached the protected handler
// and what principal (if any) it saw in the context.
type terminalHandler struct {
	called    bool
	principal Principal
	hasPrin   bool
}

func (t *terminalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.called = true
	t.principal, t.hasPrin = PrincipalFrom(r.Context())
	w.WriteHeader(http.StatusOK)
}

func TestRequireSession_NoCookie_Returns401_AndDoesNotCallNext(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})
	term := &terminalHandler{}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	srv.RequireSession(term).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if term.called {
		t.Fatal("downstream handler must not be invoked when cookie is missing")
	}
}

func TestRequireSession_UnknownSession_Returns401(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{active: map[string]*db.SessionWithUser{}})
	term := &terminalHandler{}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "no-such-session"})
	rec := httptest.NewRecorder()
	srv.RequireSession(term).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if term.called {
		t.Fatal("downstream handler must not be invoked for unknown session")
	}
}

// The DB query filters expired sessions server-side (WHERE expires_at > now()),
// so an expired session manifests to the middleware as ErrNotFound — same
// path as "unknown". This test pins that contract.
func TestRequireSession_ExpiredSessionLooksLikeMissing(t *testing.T) {
	// The stub returns ErrNotFound when the id isn't in `active`. The real
	// DB also returns no rows for expired sessions; this asserts the
	// observable behaviour matches.
	srv := newTestServer(t, &stubUsers{}, &stubSessions{
		active: map[string]*db.SessionWithUser{
			// Intentionally absent: "expired-id"
		},
	})
	term := &terminalHandler{}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "expired-id"})
	rec := httptest.NewRecorder()
	srv.RequireSession(term).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
}

func TestRequireSession_DBError_Returns500(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{
		getErr: errors.New("postgres exploded"),
	})
	term := &terminalHandler{}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "anything"})
	rec := httptest.NewRecorder()
	srv.RequireSession(term).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
}

func TestRequireSession_Valid_AttachesPrincipalAndCallsNext(t *testing.T) {
	sid := "valid-session-id"
	srv := newTestServer(t, &stubUsers{}, &stubSessions{
		active: map[string]*db.SessionWithUser{
			sid: {
				Session: db.Session{
					ID:        sid,
					UserID:    42,
					ExpiresAt: time.Now().Add(time.Hour),
				},
				UserEmail: "user@example.org",
				UserRole:  db.RoleOperator,
			},
		},
	})
	term := &terminalHandler{}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sid})
	rec := httptest.NewRecorder()
	srv.RequireSession(term).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if !term.called {
		t.Fatal("downstream handler must run for a valid session")
	}
	if !term.hasPrin {
		t.Fatal("principal must be attached to the request context")
	}
	want := Principal{UserID: 42, Email: "user@example.org", Role: db.RoleOperator, SessionID: sid}
	if term.principal != want {
		t.Fatalf("principal mismatch:\n got %+v\n want %+v", term.principal, want)
	}
}

// RequireRole tests inject the principal directly to keep them isolated from
// the cookie/DB path (which RequireSession tests cover).
func injectPrincipal(r *http.Request, p Principal) *http.Request {
	return r.WithContext(withPrincipal(r.Context(), p))
}

func TestRequireRole_NoPrincipal_Returns401(t *testing.T) {
	term := &terminalHandler{}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	RequireRole(db.RoleAdmin)(term).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 (missing RequireSession upstream)", rec.Code)
	}
	if term.called {
		t.Fatal("downstream must not run without a principal")
	}
}

func TestRequireRole_WrongRole_Returns403(t *testing.T) {
	term := &terminalHandler{}
	req := injectPrincipal(
		httptest.NewRequest(http.MethodGet, "/admin", nil),
		Principal{UserID: 1, Role: db.RoleViewer},
	)
	rec := httptest.NewRecorder()
	RequireRole(db.RoleAdmin)(term).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", rec.Code)
	}
	if term.called {
		t.Fatal("downstream must not run when role check fails")
	}
}

func TestRequireRole_AnyOfMatches(t *testing.T) {
	tests := []struct {
		name   string
		role   db.Role
		wantOK bool
	}{
		{"admin_in_admin_or_operator", db.RoleAdmin, true},
		{"operator_in_admin_or_operator", db.RoleOperator, true},
		{"viewer_in_admin_or_operator", db.RoleViewer, false},
	}
	mw := RequireRole(db.RoleAdmin, db.RoleOperator)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			term := &terminalHandler{}
			req := injectPrincipal(
				httptest.NewRequest(http.MethodGet, "/x", nil),
				Principal{UserID: 1, Role: tc.role},
			)
			rec := httptest.NewRecorder()
			mw(term).ServeHTTP(rec, req)

			if tc.wantOK {
				if rec.Code != http.StatusOK {
					t.Fatalf("status: got %d, want 200", rec.Code)
				}
				if !term.called {
					t.Fatal("downstream must run on role match")
				}
			} else {
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status: got %d, want 403", rec.Code)
				}
			}
		})
	}
}

func TestMe_UsesPrincipalFromContext(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})
	req := injectPrincipal(
		httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil),
		Principal{UserID: 7, Email: "me@example.org", Role: db.RoleAdmin, SessionID: "sid"},
	)
	rec := httptest.NewRecorder()
	srv.me(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"user_id":7`, `"email":"me@example.org"`, `"role":"admin"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q\n body: %s", want, body)
		}
	}
}

func TestMe_NoPrincipal_Returns401(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	rec := httptest.NewRecorder()
	srv.me(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
}

