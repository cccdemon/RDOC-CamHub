package httpapi

import (
	"net/http"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/auth"
)

// SessionCookieConfig holds the immutable cookie attributes for session
// cookies. Decoupled from request-time TLS detection because TLS terminates
// at the reverse proxy in production; the backend must trust its own config.
type SessionCookieConfig struct {
	Secure bool
	Domain string
}

func (c SessionCookieConfig) New(name, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   c.Domain,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

func (c SessionCookieConfig) NewClearing(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   c.Domain,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// NewSession is shorthand for the session cookie with the canonical name
// and access TTL. PR-S5: the browser cookie lives only for the access
// window; refresh must roll it forward before then. Hard cap is enforced
// server-side via sessions.created_at + SessionRefreshWindow.
func (c SessionCookieConfig) NewSession(value string) *http.Cookie {
	return c.New(auth.SessionCookieName, value, time.Now().Add(auth.SessionAccessTTL))
}

// NewCSRF returns the CSRF double-submit cookie. Same Secure/Domain/Path/
// SameSite as the session cookie, but *not* HttpOnly: the browser-side JS
// has to read it to echo it back in the X-CSRF-Token header. The token's
// secrecy comes from the same-origin policy preventing cross-site JS reads,
// not from HttpOnly.
func (c SessionCookieConfig) NewCSRF(value string) *http.Cookie {
	return &http.Cookie{
		Name:     auth.CSRFCookieName,
		Value:    value,
		Path:     "/",
		Domain:   c.Domain,
		HttpOnly: false,
		Secure:   c.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(auth.SessionAccessTTL),
	}
}

// NewClearingCSRF returns a cookie that clears the CSRF cookie (HttpOnly
// stays false to match the original; otherwise some browsers refuse the
// update).
func (c SessionCookieConfig) NewClearingCSRF() *http.Cookie {
	return &http.Cookie{
		Name:     auth.CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   c.Domain,
		HttpOnly: false,
		Secure:   c.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}
