package httpapi

import (
	"net/http"
	"testing"
	"time"
)

func TestSessionCookieConfig_New_FlagsAlwaysAsserted(t *testing.T) {
	tests := []struct {
		name     string
		cfg      SessionCookieConfig
		wantSec  bool
		wantDom  string
	}{
		{"prod_defaults", SessionCookieConfig{Secure: true}, true, ""},
		{"prod_with_domain", SessionCookieConfig{Secure: true, Domain: "api.raumdock.org"}, true, "api.raumdock.org"},
		{"dev_insecure", SessionCookieConfig{Secure: false}, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.cfg.New("camhub_session", "abc", time.Now().Add(time.Hour))
			if c.HttpOnly != true {
				t.Fatalf("HttpOnly: got %v, want true", c.HttpOnly)
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("SameSite: got %v, want Lax", c.SameSite)
			}
			if c.Secure != tc.wantSec {
				t.Fatalf("Secure: got %v, want %v", c.Secure, tc.wantSec)
			}
			if c.Domain != tc.wantDom {
				t.Fatalf("Domain: got %q, want %q", c.Domain, tc.wantDom)
			}
			if c.Path != "/" {
				t.Fatalf("Path: got %q, want %q", c.Path, "/")
			}
		})
	}
}

func TestSessionCookieConfig_NewClearing_ExpiresImmediately(t *testing.T) {
	cfg := SessionCookieConfig{Secure: true}
	c := cfg.NewClearing("camhub_session")
	if c.MaxAge >= 0 {
		t.Fatalf("MaxAge: got %d, want < 0 (clearing)", c.MaxAge)
	}
	if c.Value != "" {
		t.Fatalf("Value: got %q, want empty", c.Value)
	}
	if !c.HttpOnly || !c.Secure {
		t.Fatalf("HttpOnly/Secure must stay asserted on clear: %+v", c)
	}
}
