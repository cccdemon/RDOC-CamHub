package cloudflare

import "strings"

// reservedSubdomains blocks names a malicious enrollment must never
// claim. Plan §3 + §10 spell out the rationale: a cam that registered
// `api.raumdock.org` would silently override the API host's DNS and
// could MITM every cam→hub heartbeat.
//
// The list is deliberately broad — anything that could plausibly be
// re-used for hub infrastructure later belongs here. Adding entries is
// cheap; removing them is a security review.
var reservedSubdomains = map[string]struct{}{
	// CamHub infrastructure
	"api":     {},
	"app":     {},
	"hub":     {},
	"admin":   {},
	"camhub":  {},
	// Generic web
	"www":     {},
	"mail":    {},
	"ftp":     {},
	"smtp":    {},
	"pop":     {},
	"pop3":    {},
	"imap":    {},
	"webmail": {},
	// DNS / mail infra
	"ns":      {},
	"ns1":     {},
	"ns2":     {},
	"ns3":     {},
	"mx":      {},
	"mx1":     {},
	"mx2":     {},
	"dns":     {},
	"dkim":    {},
	"spf":     {},
	"dmarc":   {},
	// Sibling raumdock.org services that already exist (§ deploy)
	"financial": {},
	"webrtc":    {},
	"stream":    {},
	"streaming": {},
	// Cloud / k8s-flavoured patterns we might want later
	"auth":     {},
	"oauth":    {},
	"sso":      {},
	"login":    {},
	"register": {},
	"grafana":  {},
	"prom":     {},
	"prometheus": {},
	"metrics":  {},
	"status":   {},
	"health":   {},
	"healthz":  {},
	// Common attack-bait
	"root":      {},
	"test":      {},
	"staging":   {},
	"dev":       {},
	"localhost": {},
}

// IsReserved reports whether `name` is forbidden as a cam subdomain.
// Case-insensitive; trailing dots and the parent domain suffix are
// rejected as well to make the check robust against differing FQDN
// shapes (`livingroom`, `livingroom.`, `livingroom.raumdock.org`).
//
// Empty input is reserved by definition — a cam can't claim "".
func IsReserved(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return true
	}
	// Reject if the cam tries to slip past with a multi-label name like
	// "api.foo". We only enrol single-label subdomains under the parent
	// zone; multi-label is by definition not a cam slot.
	if strings.ContainsRune(n, '.') {
		return true
	}
	_, ok := reservedSubdomains[n]
	return ok
}
