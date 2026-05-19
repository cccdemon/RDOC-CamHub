package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

func TestTrustedProxyIP(t *testing.T) {
	tests := []struct {
		name       string
		trusted    []netip.Prefix
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{
			name:       "no_trusted_proxies_ignores_xff",
			trusted:    nil,
			remoteAddr: "1.2.3.4:5555",
			xff:        "9.9.9.9",
			want:       "1.2.3.4",
		},
		{
			name:       "untrusted_peer_ignores_xff",
			trusted:    []netip.Prefix{mustPrefix(t, "127.0.0.0/8")},
			remoteAddr: "1.2.3.4:5555",
			xff:        "9.9.9.9",
			want:       "1.2.3.4",
		},
		{
			name:       "trusted_peer_uses_xff",
			trusted:    []netip.Prefix{mustPrefix(t, "127.0.0.0/8")},
			remoteAddr: "127.0.0.1:5555",
			xff:        "9.9.9.9",
			want:       "9.9.9.9",
		},
		{
			name:       "trusted_peer_walks_xff_chain_to_first_untrusted",
			trusted:    []netip.Prefix{mustPrefix(t, "127.0.0.0/8"), mustPrefix(t, "10.0.0.0/8")},
			remoteAddr: "127.0.0.1:5555",
			xff:        "9.9.9.9, 10.0.0.5, 10.0.0.6",
			want:       "9.9.9.9",
		},
		{
			name:       "trusted_peer_xff_all_trusted_returns_innermost_proxy",
			trusted:    []netip.Prefix{mustPrefix(t, "127.0.0.0/8"), mustPrefix(t, "10.0.0.0/8")},
			remoteAddr: "127.0.0.1:5555",
			xff:        "10.0.0.5",
			want:       "127.0.0.1",
		},
		{
			name:       "trusted_peer_falls_back_to_x_real_ip",
			trusted:    []netip.Prefix{mustPrefix(t, "127.0.0.0/8")},
			remoteAddr: "127.0.0.1:5555",
			xRealIP:    "9.9.9.9",
			want:       "9.9.9.9",
		},
		{
			name:       "trusted_peer_malformed_xff_returns_peer",
			trusted:    []netip.Prefix{mustPrefix(t, "127.0.0.0/8")},
			remoteAddr: "127.0.0.1:5555",
			xff:        "not-an-ip",
			want:       "127.0.0.1",
		},
		{
			name:       "ipv6_peer_trusted",
			trusted:    []netip.Prefix{mustPrefix(t, "::1/128")},
			remoteAddr: "[::1]:5555",
			xff:        "9.9.9.9",
			want:       "9.9.9.9",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}

			var got netip.Addr
			handler := TrustedProxyIP(tc.trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = ClientIP(r.Context())
			}))
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if got.String() != tc.want {
				t.Fatalf("ClientIP = %s, want %s", got, tc.want)
			}
		})
	}
}
