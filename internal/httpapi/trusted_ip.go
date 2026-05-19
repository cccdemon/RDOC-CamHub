package httpapi

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
)

type ctxKeyIP struct{}

// ClientIP returns the trusted client IP attached by TrustedProxyIP. The
// zero value is returned if the middleware did not run or the address was
// unparseable.
func ClientIP(ctx context.Context) netip.Addr {
	v, _ := ctx.Value(ctxKeyIP{}).(netip.Addr)
	return v
}

// TrustedProxyIP resolves the client IP, only honouring X-Forwarded-For /
// X-Real-IP when the *immediate* peer is in trustedProxies. The resolved
// address is attached to the request context so downstream handlers and
// rate limiters share one source of truth.
//
// Behavior:
//   - peer not in trustedProxies => use the peer's address (RemoteAddr),
//     ignore forwarded headers entirely.
//   - peer in trustedProxies     => walk X-Forwarded-For right-to-left,
//     pop entries that are themselves trusted, and stop at the first
//     untrusted entry. If XFF is empty, fall back to X-Real-IP, then to
//     the peer's address.
//
// A nil/empty trustedProxies list never trusts forwarded headers.
func TrustedProxyIP(trustedProxies []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer := peerAddr(r.RemoteAddr)
			resolved := peer

			if isTrusted(peer, trustedProxies) {
				if hop, ok := walkXFF(r.Header.Values("X-Forwarded-For"), trustedProxies); ok {
					resolved = hop
				} else if real := parseAddr(r.Header.Get("X-Real-IP")); real.IsValid() {
					resolved = real
				}
			}

			ctx := context.WithValue(r.Context(), ctxKeyIP{}, resolved)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func walkXFF(headers []string, trusted []netip.Prefix) (netip.Addr, bool) {
	// chi sees one header value per RFC-line. X-Forwarded-For may also be
	// comma-separated within a single value.
	var hops []string
	for _, h := range headers {
		for _, p := range strings.Split(h, ",") {
			if p = strings.TrimSpace(p); p != "" {
				hops = append(hops, p)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr := parseAddr(hops[i])
		if !addr.IsValid() {
			return netip.Addr{}, false
		}
		if !isTrusted(addr, trusted) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// peerAddr parses a "host:port" RemoteAddr into a netip.Addr. Returns the
// zero Addr on error.
func peerAddr(remote string) netip.Addr {
	if remote == "" {
		return netip.Addr{}
	}
	if i := strings.LastIndex(remote, ":"); i > 0 {
		host := remote[:i]
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
		return parseAddr(host)
	}
	return parseAddr(remote)
}

func parseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}
	}
	return a
}
