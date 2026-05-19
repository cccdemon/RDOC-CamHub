package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// withClientIP injects a ClientIP without depending on TrustedProxyIP, keeping
// the rate-limit tests isolated from the proxy-trust logic.
func withClientIP(r *http.Request, ip netip.Addr) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyIP{}, ip))
}

func TestLoginRateLimiter_NilWhenDisabled(t *testing.T) {
	if LoginRateLimiter(RateLimitConfig{PerIP: 0, WindowSecs: 60}) != nil {
		t.Fatal("PerIP=0 should disable the limiter (return nil)")
	}
	if LoginRateLimiter(RateLimitConfig{PerIP: 5, WindowSecs: 0}) != nil {
		t.Fatal("WindowSecs=0 should disable the limiter (return nil)")
	}
}

func TestLoginRateLimiter_BlocksAfterBudget(t *testing.T) {
	mw := LoginRateLimiter(RateLimitConfig{PerIP: 3, WindowSecs: 60})
	if mw == nil {
		t.Fatal("limiter should not be nil")
	}

	called := 0
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	ip := netip.MustParseAddr("1.2.3.4")
	hit := func() int {
		req := withClientIP(httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil), ip)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 3; i++ {
		if code := hit(); code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, code)
		}
	}
	if code := hit(); code != http.StatusTooManyRequests {
		t.Fatalf("4th request: got %d, want 429", code)
	}
	if called != 3 {
		t.Fatalf("downstream called %d times, want 3", called)
	}
}

func TestLoginRateLimiter_PerIPIsolation(t *testing.T) {
	mw := LoginRateLimiter(RateLimitConfig{PerIP: 1, WindowSecs: 60})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	hit := func(s string) int {
		req := withClientIP(httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil), netip.MustParseAddr(s))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := hit("1.2.3.4"); code != http.StatusOK {
		t.Fatalf("1.2.3.4 first: got %d, want 200", code)
	}
	if code := hit("1.2.3.4"); code != http.StatusTooManyRequests {
		t.Fatalf("1.2.3.4 second: got %d, want 429", code)
	}
	if code := hit("5.6.7.8"); code != http.StatusOK {
		t.Fatalf("5.6.7.8 first: got %d, want 200 (separate bucket)", code)
	}
}

func TestIPLimiter_RefillOverWindow(t *testing.T) {
	l := newIPLimiter(2, 60*time.Second)
	ip := netip.MustParseAddr("1.2.3.4")
	t0 := time.Now()

	if !l.allow(ip, t0) || !l.allow(ip, t0) {
		t.Fatal("first two requests in window should pass")
	}
	if l.allow(ip, t0) {
		t.Fatal("third request in same instant should fail")
	}
	// Half a window later → +1 token refilled.
	if !l.allow(ip, t0.Add(30*time.Second)) {
		t.Fatal("request after half window should pass (1 token refilled)")
	}
	if l.allow(ip, t0.Add(30*time.Second)) {
		t.Fatal("request right after refill should fail again")
	}
}
