package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// stubUsers lets us drive login without standing up Postgres.
type stubUsers struct {
	users  map[string]*db.User
	called int
}

func (s *stubUsers) ByEmail(_ context.Context, email string) (*db.User, error) {
	s.called++
	if u, ok := s.users[email]; ok {
		return u, nil
	}
	return nil, db.ErrNotFound
}

// stubSessions implements SessionWriter against an in-memory map keyed by
// session id. RequireSession-driven tests populate `active` with the
// SessionWithUser they want to return for a given cookie value; the
// pre-session-create branches in login don't touch any of this.
type stubSessions struct {
	created int
	active  map[string]*db.SessionWithUser
	getErr  error
}

func (n *stubSessions) Create(_ context.Context, _ string, _ int64, _ time.Duration, _ string, _ netip.Addr) error {
	n.created++
	return nil
}
func (n *stubSessions) Get(_ context.Context, _ string) (*db.Session, error) {
	return nil, db.ErrNotFound
}
func (n *stubSessions) GetActiveWithUser(_ context.Context, id string) (*db.SessionWithUser, error) {
	if n.getErr != nil {
		return nil, n.getErr
	}
	if swu, ok := n.active[id]; ok {
		return swu, nil
	}
	return nil, db.ErrNotFound
}
func (n *stubSessions) Delete(_ context.Context, _ string) error { return nil }

func newTestServer(t *testing.T, users UserLookup, sessions SessionWriter) *Server {
	t.Helper()
	return &Server{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		Users:    users,
		Sessions: sessions,
		Cookies:  SessionCookieConfig{Secure: true},
	}
}

func doLogin(t *testing.T, srv *Server, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Pretend TrustedProxyIP ran; otherwise rate-limit/IP code can't run, but
	// these tests don't exercise that middleware anyway.
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyIP{}, netip.MustParseAddr("1.2.3.4")))

	rec := httptest.NewRecorder()
	srv.login(rec, req)
	return rec
}

func TestLogin_BodyTooLarge_Returns413_BeforeDB(t *testing.T) {
	users := &stubUsers{users: map[string]*db.User{}}
	srv := newTestServer(t, users, &stubSessions{})

	// 5 KiB body — well over loginMaxBody (4 KiB).
	junk := strings.Repeat("x", 5*1024)
	body := []byte(`{"email":"a@b.com","password":"` + junk + `"}`)

	rec := doLogin(t, srv, body)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: got %d, want 413", rec.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, rec.Body.String())
	}
	if resp["error"] != "body_too_large" {
		t.Fatalf("error code: got %q, want body_too_large", resp["error"])
	}
	if users.called != 0 {
		t.Fatalf("DB called %d times; should never be reached for 413", users.called)
	}
}

func TestLogin_PasswordTooLong_Returns400_BeforeArgon2AndBeforeDB(t *testing.T) {
	users := &stubUsers{users: map[string]*db.User{}}
	srv := newTestServer(t, users, &stubSessions{})

	// Password exactly 1025 chars — one over the cap. Email kept short so
	// the whole body still fits inside MaxBytesReader (4 KiB).
	longPassword := strings.Repeat("p", maxPasswordLen+1)
	body := []byte(`{"email":"a@b.com","password":"` + longPassword + `"}`)

	start := time.Now()
	rec := doLogin(t, srv, body)
	elapsed := time.Since(start)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400 (body=%q)", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "bad_request" {
		t.Fatalf("error code: got %q, want bad_request", resp["error"])
	}
	if !strings.Contains(strings.ToLower(resp["message"]), "length") {
		t.Fatalf("message should mention length, got %q", resp["message"])
	}
	if users.called != 0 {
		t.Fatalf("DB called %d times; length cap must run before Users.ByEmail", users.called)
	}
	// Argon2id with our params is ~50ms+. 25ms is a conservative ceiling that
	// proves we exited before hashing without being flaky on slow CI.
	if elapsed > 25*time.Millisecond {
		t.Fatalf("login took %v; length cap should reject before Argon2id runs", elapsed)
	}
}

func TestLogin_EmailTooLong_Returns400_BeforeDB(t *testing.T) {
	users := &stubUsers{users: map[string]*db.User{}}
	srv := newTestServer(t, users, &stubSessions{})

	longEmail := strings.Repeat("a", maxEmailLen) + "@b.com" // > 320 chars
	body := []byte(`{"email":"` + longEmail + `","password":"shortpass"}`)

	rec := doLogin(t, srv, body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
	if users.called != 0 {
		t.Fatalf("DB called %d times; length cap must run before Users.ByEmail", users.called)
	}
}

// Error parity: unknown-email and wrong-password must return byte-identical
// response bodies (and identical status codes). This is the documented
// defense against account enumeration.
func TestLogin_ErrorParity_UnknownEmail_vs_WrongPassword(t *testing.T) {
	hash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	users := &stubUsers{users: map[string]*db.User{
		"known@example.org": {ID: 1, Email: "known@example.org", PasswordHash: hash, Role: db.RoleAdmin},
	}}
	srv := newTestServer(t, users, &stubSessions{})

	unknown := doLogin(t, srv, []byte(`{"email":"missing@example.org","password":"whatever"}`))
	wrong := doLogin(t, srv, []byte(`{"email":"known@example.org","password":"not-the-right-one"}`))

	if unknown.Code != http.StatusUnauthorized {
		t.Fatalf("unknown-email status: got %d, want 401", unknown.Code)
	}
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-password status: got %d, want 401", wrong.Code)
	}
	if got, want := unknown.Body.String(), wrong.Body.String(); got != want {
		t.Fatalf("response bodies must be identical for parity\n unknown: %s\n wrong:   %s", got, want)
	}
}
