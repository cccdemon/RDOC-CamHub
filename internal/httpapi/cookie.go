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
// and TTL.
func (c SessionCookieConfig) NewSession(value string) *http.Cookie {
	return c.New(auth.SessionCookieName, value, time.Now().Add(auth.SessionTTL))
}
