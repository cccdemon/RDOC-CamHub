package webui

import (
	"net/http"
	"strings"
)

// HostRouter dispatches between the API host and the UI host on a single
// listener. Plan §17.1: one binary serves both origins. This split is the
// load-bearing isolation between the JSON API surface and the HTML
// surface — XSS on the UI host cannot read JSON endpoints from the same
// origin, because those endpoints 404 there.
//
// Hosts are matched case-insensitively against the request Host header
// with any :port suffix stripped. Empty AppHost OR empty APIHost means
// "no split configured" → all requests go to apiHandler (the historical
// JSON-only behaviour, used in dev where the operator hits :8080 directly).
type HostRouter struct {
	AppHost    string // e.g. "app.camhub.raumdock.org"
	APIHost    string // e.g. "api.camhub.raumdock.org"
	UIHandler  http.Handler
	APIHandler http.Handler
}

func (h *HostRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// No split configured (local dev) → everything to the API handler.
	// The UI is reachable via its own routes on that same handler when
	// httpapi mounts them (see router.go: the UI routes are mounted
	// unconditionally if AppHost is empty, so dev can browse to /login).
	if h.AppHost == "" || h.APIHost == "" {
		h.APIHandler.ServeHTTP(w, r)
		return
	}

	host := hostname(r.Host)
	switch host {
	case h.AppHost:
		h.UIHandler.ServeHTTP(w, r)
	case h.APIHost:
		h.APIHandler.ServeHTTP(w, r)
	default:
		// Unknown host on a configured deployment — refuse. This is the
		// belt-and-suspenders defence: the reverse proxy already filters
		// by SNI, but if somebody points DNS at the backend directly we
		// don't want to silently serve either surface.
		http.NotFound(w, r)
	}
}

// hostname strips any :port suffix and lowercases. IPv6 literals ("[::1]:8080")
// keep their brackets but lose the trailing :port; for this app's use case
// (Caddy in front, hostnames only) the simpler split is sufficient.
func hostname(h string) string {
	h = strings.ToLower(h)
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.HasSuffix(h[:i], "]") {
		h = h[:i]
	}
	return h
}
