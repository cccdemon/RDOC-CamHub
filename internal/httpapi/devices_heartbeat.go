package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"

	"github.com/raumdock/rdoc-camhub/internal/cloudflare"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// heartbeatMaxBody caps the body. Plan §4.2 sends a small JSON payload
// (~ few hundred bytes); 8 KiB is generous headroom.
const heartbeatMaxBody = 8 << 10

// heartbeatReq is the cam-side payload (Plan §4.2). All fields are
// optional except public_ip — a heartbeat without an address would
// only update last_seen, but Plan calls for IP refresh on every beat.
//
// `status` is accepted for forward-compatibility but currently folded
// into stream_health. A dedicated cam_status column lands when the
// admin UI starts surfacing it (UI-M1 / Plan §17.5).
type heartbeatReq struct {
	PublicIP     string `json:"public_ip"`
	PublicIPv6   string `json:"public_ipv6,omitempty"`
	Status       string `json:"status,omitempty"`
	StreamHealth string `json:"stream_health,omitempty"`
	Version      string `json:"version,omitempty"`
}

// heartbeatDevice handles POST /v1/devices/heartbeat. Plan §4.2.
//
// Order:
//   1. Config-guard (same posture as register).
//   2. Bearer JWT → Verify → claims.
//   3. Body parse + IP validation.
//   4. Devices.GetByID; 401 (not 404) when missing so we don't leak
//      which device_ids the hub knows about.
//   5. Subdomain mismatch between claim and row → 401 (signed JWT
//      claims a name that no longer matches; either the row was
//      renamed by an admin or the JWT is forged for an existing id).
//   6. Devices.UpdateHeartbeat — bumps last_seen + status='online',
//      overwrites stream_health/version.
//   7. If IPv4 changed → Cloudflare UpdateRecord + dns_records upsert.
//   8. If IPv6 added/changed → CF Update or Create + dns_records.
//   9. 204 No Content. DNS sync failures are LOGGED but DON'T fail
//      the heartbeat — the cam needs liveness confirmation regardless;
//      ops can investigate the warning and the next beat will retry.
func (s *Server) heartbeatDevice(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, heartbeatMaxBody)

	if s.DeviceJWT == nil || s.CFClient == nil || s.ParentDomain == "" {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "device heartbeat is not enabled on this hub")
		return
	}

	rawToken, ok := bearerToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
		return
	}
	claims, err := s.DeviceJWT.Verify(rawToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid device token")
		return
	}

	var req heartbeatReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds size limit")
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	v4, err := netip.ParseAddr(req.PublicIP)
	if err != nil || !v4.Is4() {
		writeError(w, http.StatusBadRequest, "bad_request", "public_ip must be a valid IPv4 address")
		return
	}
	var v6 netip.Addr
	if req.PublicIPv6 != "" {
		parsed, err := netip.ParseAddr(req.PublicIPv6)
		if err != nil || !parsed.Is6() || parsed.Is4In6() {
			writeError(w, http.StatusBadRequest, "bad_request", "public_ipv6 must be a valid IPv6 address")
			return
		}
		v6 = parsed
	}

	ctx := r.Context()

	// Look up the device. 401 (not 404) for unknown — uniform with the
	// invalid-JWT response so an attacker can't enumerate device ids by
	// poking the heartbeat endpoint.
	dev, err := s.Devices.GetByID(ctx, claims.DeviceID)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "device not registered")
		return
	}
	if err != nil {
		s.Logger.Error("heartbeat: device lookup", "err", err, "device_id", claims.DeviceID)
		writeError(w, http.StatusInternalServerError, "internal", "lookup failed")
		return
	}

	// Subdomain claim vs. row mismatch. We don't support renaming a cam
	// today, so any divergence means the JWT and the row are out of
	// sync — refuse rather than write a heartbeat against a row the
	// cam thinks it's a different cam against. Same 401 envelope.
	if claims.Subdomain != dev.Subdomain {
		s.Logger.Warn("heartbeat: subdomain claim mismatch",
			"device_id", claims.DeviceID,
			"claim_sub", claims.Subdomain,
			"row_sub", dev.Subdomain)
		writeError(w, http.StatusUnauthorized, "unauthorized", "device token stale")
		return
	}

	// Combine cam-reported status into stream_health for now. Plan §4.2
	// nominates both fields; we'll split into a dedicated cam_status
	// column when UI-M1 surfaces it.
	streamHealth := req.StreamHealth
	if req.Status != "" {
		if streamHealth != "" {
			streamHealth = req.Status + " · " + streamHealth
		} else {
			streamHealth = req.Status
		}
	}

	if _, err := s.Devices.UpdateHeartbeat(ctx, dev.ID, &db.HeartbeatUpdate{
		PublicIP:     v4,
		PublicIPv6:   v6,
		StreamHealth: streamHealth,
		CamVersion:   req.Version,
	}); err != nil {
		s.Logger.Error("heartbeat: update device", "err", err, "device_id", dev.ID)
		writeError(w, http.StatusInternalServerError, "internal", "heartbeat update failed")
		return
	}

	// DNS reconciliation. Compared against the device's stored IPs
	// (pre-update view). On any CF/store error we log but do NOT fail
	// the heartbeat — the cam needs liveness regardless, and the next
	// beat will retry.
	fullName := fqdn(dev.Subdomain, s.ParentDomain)
	if !dev.PublicIP.IsValid() || dev.PublicIP.Compare(v4) != 0 {
		s.syncDNS(ctx, dev.ID, fullName, db.DNSTypeA, cloudflare.TypeA, v4.String())
	}
	switch {
	case v6.IsValid() && (!dev.PublicIPv6.IsValid() || dev.PublicIPv6.Compare(v6) != 0):
		s.syncDNS(ctx, dev.ID, fullName, db.DNSTypeAAAA, cloudflare.TypeAAAA, v6.String())
	case !v6.IsValid() && dev.PublicIPv6.IsValid():
		// Cam previously reported IPv6 and now doesn't. We deliberately
		// leave the AAAA record in place — IPv6 connectivity often
		// flaps and removing the record on a single absence would
		// destabilise resolution. A future PR can add a sustained-
		// absence policy.
		s.Logger.Debug("heartbeat: ipv6 dropped, keeping AAAA record", "device_id", dev.ID)
	}

	w.WriteHeader(http.StatusNoContent)
}

// syncDNS pushes one (A or AAAA) record value to Cloudflare and mirrors
// the result into dns_records. Logs warnings on any failure; never
// returns an error because the heartbeat handler ignores its outcome.
//
// The lookup-or-create flow handles three cases:
//
//   - dns_records row exists → UpdateRecord on the stored cf_id.
//   - dns_records row missing (e.g. register didn't persist it, or
//     this is a newly-added AAAA) → CreateRecord, then upsert.
//   - CF call fails → log, leave dns_records row alone. Next heartbeat
//     will retry with the same value.
func (s *Server) syncDNS(ctx context.Context, deviceID, fqdn string, dbType db.DNSRecordType, cfType cloudflare.RecordType, value string) {
	existing, err := s.DNSRecords.Get(ctx, deviceID, dbType)
	switch {
	case errors.Is(err, db.ErrNotFound):
		// No prior row → create at CF.
		cfID, err := s.CFClient.CreateRecord(ctx, fqdn, cfType, value)
		if err != nil {
			s.Logger.Warn("heartbeat: CF CreateRecord failed", "err", err, "device_id", deviceID, "type", cfType)
			return
		}
		if err := s.DNSRecords.Upsert(ctx, &db.DNSRecord{
			DeviceID:     deviceID,
			FQDN:         fqdn,
			Type:         dbType,
			Value:        value,
			CloudflareID: cfID,
		}); err != nil {
			s.Logger.Warn("heartbeat: dns_records upsert after create", "err", err, "device_id", deviceID, "type", cfType)
		}
		return

	case err != nil:
		s.Logger.Warn("heartbeat: dns_records lookup", "err", err, "device_id", deviceID, "type", cfType)
		return
	}

	// Existing row. UpdateRecord against CF using the cached cf_id.
	if err := s.CFClient.UpdateRecord(ctx, existing.CloudflareID, fqdn, cfType, value); err != nil {
		s.Logger.Warn("heartbeat: CF UpdateRecord failed", "err", err, "device_id", deviceID, "cf_id", existing.CloudflareID)
		return
	}
	// Mirror to dns_records so the local view matches CF.
	if err := s.DNSRecords.Upsert(ctx, &db.DNSRecord{
		DeviceID:     deviceID,
		FQDN:         fqdn,
		Type:         dbType,
		Value:        value,
		CloudflareID: existing.CloudflareID,
	}); err != nil {
		s.Logger.Warn("heartbeat: dns_records upsert after update", "err", err, "device_id", deviceID, "type", cfType)
	}
}
