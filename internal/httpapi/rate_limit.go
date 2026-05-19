package httpapi

import (
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// RateLimitConfig configures LoginRateLimiter. PerIP is the allowed request
// count per window; WindowSecs is the rolling window size in seconds.
type RateLimitConfig struct {
	PerIP      int
	WindowSecs int
}

// LoginRateLimiter returns middleware that token-buckets per client IP
// (resolved via TrustedProxyIP). Requests beyond the configured rate get a
// 429 with a Retry-After header. Returns nil if rate limiting is disabled.
func LoginRateLimiter(cfg RateLimitConfig) func(http.Handler) http.Handler {
	if cfg.PerIP <= 0 || cfg.WindowSecs <= 0 {
		return nil
	}
	limiter := newIPLimiter(cfg.PerIP, time.Duration(cfg.WindowSecs)*time.Second)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r.Context())
			// Defensive: in production TrustedProxyIP always sets a valid
			// address (peer addr if nothing else). An invalid ClientIP means
			// the middleware was skipped or RemoteAddr was unparseable —
			// both indicate a misconfiguration we shouldn't paper over by
			// silently bypassing rate limiting. Fail closed.
			if !ip.IsValid() {
				writeError(w, http.StatusServiceUnavailable, "client_ip_unknown", "cannot identify client")
				return
			}
			if !limiter.allow(ip, time.Now()) {
				w.Header().Set("Retry-After", "60")
				writeError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts, slow down")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ipLimiter is a tiny in-process token bucket keyed by client IP. One bucket
// per IP, lazily created. Buckets get garbage-collected on the next sweep
// after they've been idle for >= window.
//
// Single-process only. M0.5 ships a single hub instance; if we ever scale
// horizontally, this moves to Redis.
type ipLimiter struct {
	max    int
	window time.Duration

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	return &ipLimiter{
		max:     max,
		window:  window,
		buckets: make(map[netip.Addr]*bucket),
		lastGC:  time.Now(),
	}
}

func (l *ipLimiter) allow(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) >= l.window {
		for k, b := range l.buckets {
			if now.Sub(b.last) >= l.window {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}

	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: float64(l.max), last: now}
		l.buckets[ip] = b
	}
	// Refill linearly over the window.
	elapsed := now.Sub(b.last).Seconds()
	refill := elapsed / l.window.Seconds() * float64(l.max)
	b.tokens = minF(float64(l.max), b.tokens+refill)
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
