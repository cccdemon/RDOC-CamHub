package cloudflare

import "testing"

func TestIsReserved(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Hub infra — load-bearing rejections
		{"api", true},
		{"app", true},
		{"hub", true},
		{"camhub", true},

		// Case-insensitive
		{"API", true},
		{"Admin", true},

		// Trailing dot — the FQDN form must be canonicalised
		{"api.", true},

		// Multi-label — cams may only claim single-label names
		{"api.foo", true},
		{"livingroom.raumdock.org", true},

		// Empty / whitespace
		{"", true},
		{"   ", true},
		{"  api  ", true}, // trim-then-check

		// Mail / DNS infra
		{"mail", true},
		{"ns1", true},
		{"dmarc", true},

		// Sibling raumdock services (per memory: financial, webrtc on
		// the same LXC). Reserving them stops a cam from shadowing.
		{"financial", true},
		{"webrtc", true},

		// Common attack-bait
		{"login", true},
		{"oauth", true},
		{"healthz", true},

		// Legitimate cam names — must NOT be reserved
		{"livingroom", false},
		{"bedroom", false},
		{"mobile1", false},
		{"cam1", false}, // existing per Plan §3
		{"garage", false},
		{"front-door", false},
		// Single letter is allowed: not on the reserved list, no reason
		// to block. If we change our mind later, add to the map.
		{"a", false},
		{"x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsReserved(tc.name)
			if got != tc.want {
				t.Errorf("IsReserved(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
