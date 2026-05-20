package config

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Listen   string
	DBURL    string
	LogLevel slog.Level

	// Cookie defaults applied by httpapi to session/CSRF cookies.
	CookieSecure bool
	CookieDomain string

	// TrustedProxies is the CIDR allow-list whose X-Forwarded-For /
	// X-Real-IP headers we honour. Empty => never trust forwarded headers
	// (use RemoteAddr instead). This is the prod-safe default; setting it
	// to a non-empty list is a deliberate trust-boundary decision.
	TrustedProxies []netip.Prefix

	// Login rate limiting. 0 in either field disables the limiter.
	LoginRateLimitPerIP      int
	LoginRateLimitWindowSecs int

	// AllowedOrigins is the explicit Origin/Referer allow-list used by the
	// CSRF middleware as defense-in-depth. Each entry is a full origin
	// (scheme + host [+ :port]), e.g. "https://app.raumdock.org".
	// Empty list => Origin/Referer check is skipped; the double-submit
	// token alone gates the request. Set in production.
	AllowedOrigins []string

	// AppHost / APIHost split the JSON API surface from the HTML UI
	// surface across two hostnames on the same listener (Plan §17.1).
	// Both empty = dev/test (single mux). Setting only one is a config
	// error and aborts startup.
	//
	// APIBase is the absolute origin (e.g. "https://api.camhub.raumdock.org")
	// the UI's JS uses for cross-origin fetches. Empty = same-origin.
	AppHost string
	APIHost string
	APIBase string

	// Device-side wiring (Plan §3 + §4). All four required for the M1
	// register/heartbeat endpoints.
	//
	//   ParentDomain         — DNS zone cams enrol under (e.g. raumdock.org).
	//   CFAPIToken           — Cloudflare API token, Zone:DNS:Edit scope.
	//   CFZoneID             — the zone id ParentDomain resolves to.
	//   DeviceJWTRingFile    — secrets/device_jwt_ring.json path.
	//   HubCertFingerprint   — SHA-256 fingerprint cams pin (TOFU); optional.
	ParentDomain       string
	CFAPIToken         string
	CFZoneID           string
	DeviceJWTRingFile  string
	HubCertFingerprint string
}

func Load() (*Config, error) {
	c := &Config{
		Listen:       envOr("CAMHUB_LISTEN", ":8080"),
		LogLevel:     parseLevel(envOr("CAMHUB_LOG_LEVEL", "info")),
		CookieSecure: true,
		CookieDomain: os.Getenv("CAMHUB_COOKIE_DOMAIN"),
	}

	// Local plain-HTTP dev only. Refuses to be a default.
	if envBool("CAMHUB_DEV_INSECURE_COOKIE") {
		c.CookieSecure = false
	}

	if raw := os.Getenv("CAMHUB_TRUSTED_PROXIES"); raw != "" {
		prefixes, err := parseCIDRList(raw)
		if err != nil {
			return nil, fmt.Errorf("trusted proxies: %w", err)
		}
		c.TrustedProxies = prefixes
	}

	perIP, err := envInt("CAMHUB_LOGIN_RATE_PER_IP", 10)
	if err != nil {
		return nil, err
	}
	c.LoginRateLimitPerIP = perIP

	windowSecs, err := envInt("CAMHUB_LOGIN_RATE_WINDOW_SECS", 60)
	if err != nil {
		return nil, err
	}
	c.LoginRateLimitWindowSecs = windowSecs

	if raw := os.Getenv("CAMHUB_ALLOWED_ORIGINS"); raw != "" {
		c.AllowedOrigins = parseCommaList(raw)
	}

	c.AppHost = strings.TrimSpace(os.Getenv("CAMHUB_APP_HOST"))
	c.APIHost = strings.TrimSpace(os.Getenv("CAMHUB_API_HOST"))
	c.APIBase = strings.TrimSpace(os.Getenv("CAMHUB_API_BASE"))
	if (c.AppHost == "") != (c.APIHost == "") {
		return nil, fmt.Errorf("host split: CAMHUB_APP_HOST and CAMHUB_API_HOST must both be set or both empty")
	}

	dbURL, err := readSecret("CAMHUB_DB_URL", "CAMHUB_DB_URL_FILE")
	if err != nil {
		return nil, fmt.Errorf("db url: %w", err)
	}
	c.DBURL = dbURL

	// Device-side config. Optional in dev so `go run ./cmd/camhub serve`
	// works pre-M1; the device endpoints fail closed at request time
	// when these are unset, which is the right behaviour pre-rollout.
	c.ParentDomain = strings.TrimSpace(os.Getenv("CAMHUB_PARENT_DOMAIN"))
	c.CFZoneID = strings.TrimSpace(os.Getenv("CAMHUB_CF_ZONE_ID"))
	c.DeviceJWTRingFile = strings.TrimSpace(os.Getenv("CAMHUB_DEVICE_JWT_RING_FILE"))
	c.HubCertFingerprint = strings.TrimSpace(os.Getenv("CAMHUB_HUB_CERT_FINGERPRINT"))

	// CF token follows the same FILE-or-inline pattern as DB URL.
	// Optional: empty token disables Cloudflare (dev/local). Handler
	// startup-checks the combination so production never half-configures.
	if path := os.Getenv("CAMHUB_CF_API_TOKEN_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read CAMHUB_CF_API_TOKEN_FILE=%q: %w", path, err)
		}
		c.CFAPIToken = strings.TrimRight(string(b), "\r\n")
	} else if v := os.Getenv("CAMHUB_CF_API_TOKEN"); v != "" {
		c.CFAPIToken = v
	}

	return c, nil
}

// readSecret prefers the *_FILE form (Docker-secret-friendly). Falls back to
// the inline env var only if the file form is absent — useful for local `go run`.
func readSecret(envVar, fileVar string) (string, error) {
	if path := os.Getenv(fileVar); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s=%q: %w", fileVar, path, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if v := os.Getenv(envVar); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("neither %s nor %s set", envVar, fileVar)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q: %w", key, v, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s: must be >= 0, got %d", key, n)
	}
	return n, nil
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// parseCommaList splits a comma-separated env value, trims whitespace
// around each entry, and drops empty entries.
func parseCommaList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseCIDRList(s string) ([]netip.Prefix, error) {
	parts := strings.Split(s, ",")
	out := make([]netip.Prefix, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pref, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", p, err)
		}
		out = append(out, pref)
	}
	return out, nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
