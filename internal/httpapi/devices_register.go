package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/cloudflare"
	"github.com/raumdock/rdoc-camhub/internal/db"
	"github.com/raumdock/rdoc-camhub/internal/devicejwt"
)

// registerMaxBody caps the device-register body. The legitimate shape
// (device_id, preferred_name, IPs, ports, capabilities) is well under
// 8 KiB even with a verbose capabilities descriptor. 16 KiB is a
// comfortable cap that still rejects gigantic payloads early.
const registerMaxBody = 16 << 10

// Device-id and preferred-name length caps. The cam controls both
// strings; capping is defense-in-depth against accidentally-huge
// device ids polluting indexes.
const (
	maxDeviceIDLen      = 128
	maxPreferredNameLen = 63 // matches the DNS label cap
)

// registerReq is the cam-side payload (Plan §4.1). public_ipv6 is
// optional — many cams sit behind IPv4-only NAT. ports and
// capabilities are JSON-shaped descriptors we store verbatim.
type registerReq struct {
	DeviceID      string          `json:"device_id"`
	PreferredName string          `json:"preferred_name"`
	PublicIP      string          `json:"public_ip"`
	PublicIPv6    string          `json:"public_ipv6,omitempty"`
	Ports         json.RawMessage `json:"ports,omitempty"`
	Capabilities  json.RawMessage `json:"capabilities,omitempty"`
}

// registerResp is the hub-side response. assigned_subdomain may
// differ from the requested preferred_name (collision suffix).
// hub_cert_fingerprint is the cam's TOFU pin target; empty when not
// configured (dev/local).
type registerResp struct {
	AssignedSubdomain  string `json:"assigned_subdomain"`
	DeviceJWT          string `json:"device_jwt"`
	HubCertFingerprint string `json:"hub_cert_fingerprint,omitempty"`
}

// registerDevice handles POST /v1/devices/register. Plan §4.1.
//
// Flow:
//
//  1. Parse and validate the body, length-cap before any heavy work.
//  2. Extract the enrollment Bearer token, hash it.
//  3. Validate subdomain (reserved-name check, label rule).
//  4. **Consume the enrollment token** (atomic UPDATE … WHERE
//     consumed_at IS NULL AND expires_at > now()). Plan §4.1 says
//     "token is burned regardless of outcome on the hub side" — so
//     once we have exclusive use of the token, everything below this
//     line that fails just costs the admin a fresh enrollment.
//  5. Resolve subdomain (collision suffix).
//  6. Create Cloudflare A (always) and AAAA (if cam reported IPv6).
//  7. Insert the device row. On failure: rollback CF records (best
//     effort) and 500.
//  8. Sign the device JWT. On failure: rollback CF records + delete
//     the device row.
//  9. Upsert dns_records pointers (non-fatal — IP-change recovery
//     can re-list CF later).
//  10. Return assigned_subdomain + device_jwt + hub_cert_fingerprint.
//
// Failure responses for an unusable token collapse to 401 (unknown vs
// consumed vs expired — no oracle).
func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, registerMaxBody)

	// Fail closed if the operator hasn't completed M1 wiring (no JWT
	// ring, no CF client, or no parent domain). Better to surface a
	// loud 503 here than to silently let the handler panic deep inside
	// a partial transaction.
	if s.DeviceJWT == nil || s.CFClient == nil || s.ParentDomain == "" {
		s.Logger.Error("register: device endpoints not fully configured",
			"have_jwt_ring", s.DeviceJWT != nil,
			"have_cf_client", s.CFClient != nil,
			"have_parent_domain", s.ParentDomain != "")
		writeError(w, http.StatusServiceUnavailable, "not_configured", "device enrollment is not enabled on this hub")
		return
	}

	rawToken, ok := bearerToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
		return
	}

	var req registerReq
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

	// Sanity-validate the cam-supplied strings before touching the DB.
	if len(req.DeviceID) == 0 || len(req.DeviceID) > maxDeviceIDLen {
		writeError(w, http.StatusBadRequest, "bad_request", "device_id is required and at most 128 chars")
		return
	}
	if len(req.PreferredName) == 0 || len(req.PreferredName) > maxPreferredNameLen {
		writeError(w, http.StatusBadRequest, "bad_request", "preferred_name is required and at most 63 chars")
		return
	}
	base, err := validateSubdomain(req.PreferredName)
	switch {
	case errors.Is(err, ErrSubdomainInvalid):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	case errors.Is(err, ErrSubdomainReserved):
		writeError(w, http.StatusBadRequest, "reserved_name", "preferred_name is reserved")
		return
	case err != nil:
		s.Logger.Error("register: validate subdomain", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "validation failed")
		return
	}

	// Parse IPs. IPv4 is required; IPv6 is optional and a parse error
	// on IPv6 fails the whole request (a malformed cam payload is
	// safer to reject than silently swallow).
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
	tokenHash := auth.HashEnrollmentToken(rawToken)

	// Consume the token FIRST. Plan §4.1: token burns regardless of
	// outcome. Doing this up front means a downstream failure (CF
	// outage, DB error, sign failure) doesn't leave us with a row that
	// blocks retry under a fresh token — the cam will just get a new
	// token and try again.
	if err := s.EnrollmentTokens.Consume(ctx, tokenHash, req.DeviceID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			// Unknown / consumed / expired: indistinguishable to the
			// caller by design.
			writeError(w, http.StatusUnauthorized, "unauthorized", "enrollment token not usable")
			return
		}
		s.Logger.Error("register: token consume", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "token consume failed")
		return
	}

	// From here on, the token is gone. Any failure costs an enrollment.

	assigned, err := resolveSubdomain(ctx, s.Devices, base)
	if errors.Is(err, ErrSubdomainExhausted) {
		writeError(w, http.StatusConflict, "subdomain_exhausted", "too many collisions; pick a different preferred_name")
		return
	}
	if err != nil {
		s.Logger.Error("register: resolve subdomain", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "lookup failed")
		return
	}

	parentZone := s.ParentDomain
	if parentZone == "" {
		s.Logger.Error("register: ParentDomain not configured")
		writeError(w, http.StatusInternalServerError, "internal", "hub misconfigured")
		return
	}
	fullName := fqdn(assigned, parentZone)

	// External step: Cloudflare. We do this BEFORE the DB write so a
	// CF failure leaves no orphaned device row. If CF succeeds but
	// the DB write fails, we attempt a CF delete on the way out.
	aRecordID, err := s.CFClient.CreateRecord(ctx, fullName, cloudflare.TypeA, v4.String())
	if err != nil {
		s.Logger.Error("register: cloudflare CreateRecord A", "err", err, "fqdn", fullName)
		writeError(w, http.StatusBadGateway, "dns_failed", "failed to create A record")
		return
	}

	var aaaaRecordID string
	if v6.IsValid() {
		aaaaRecordID, err = s.CFClient.CreateRecord(ctx, fullName, cloudflare.TypeAAAA, v6.String())
		if err != nil {
			s.Logger.Error("register: cloudflare CreateRecord AAAA", "err", err, "fqdn", fullName)
			s.bestEffortCFDelete(ctx, aRecordID)
			writeError(w, http.StatusBadGateway, "dns_failed", "failed to create AAAA record")
			return
		}
	}

	// DB step. Any failure here triggers CF cleanup so the records
	// don't leak. The cleanup is best-effort: a failed delete is
	// logged but not surfaced to the cam (the request already failed
	// for a different reason).
	dev, err := s.Devices.Create(ctx, &db.DeviceRegistration{
		ID:           req.DeviceID,
		Name:         req.PreferredName,
		Subdomain:    assigned,
		DeviceJWTKID: s.DeviceJWT.SigningKID(),
		Capabilities: req.Capabilities,
		Ports:        req.Ports,
		PublicIP:     v4,
		PublicIPv6:   v6,
	})
	if err != nil {
		s.Logger.Error("register: insert device", "err", err, "device_id", req.DeviceID)
		s.bestEffortCFDelete(ctx, aRecordID)
		if aaaaRecordID != "" {
			s.bestEffortCFDelete(ctx, aaaaRecordID)
		}
		writeError(w, http.StatusInternalServerError, "internal", "device insert failed")
		return
	}

	// Sign the JWT. On failure we roll BOTH the device row AND the CF
	// records back — token is already gone, but we don't want the
	// orphan footprint to confuse later operations.
	signed, err := s.DeviceJWT.Sign(devicejwt.Claims{
		DeviceID:  dev.ID,
		Subdomain: assigned,
	})
	if err != nil {
		s.Logger.Error("register: sign device jwt", "err", err)
		s.bestEffortDeviceDelete(ctx, dev.ID)
		s.bestEffortCFDelete(ctx, aRecordID)
		if aaaaRecordID != "" {
			s.bestEffortCFDelete(ctx, aaaaRecordID)
		}
		writeError(w, http.StatusInternalServerError, "internal", "jwt sign failed")
		return
	}

	// Upsert dns_records pointers. Failure here is logged but does
	// NOT fail the request — the cam is already happy with its JWT
	// and CF records exist. Missing pointers just mean heartbeat-side
	// IP updates degrade to "re-list and search" (not implemented yet
	// but a known fallback path).
	if err := s.DNSRecords.Upsert(ctx, &db.DNSRecord{
		DeviceID:     dev.ID,
		FQDN:         fullName,
		Type:         db.DNSTypeA,
		Value:        v4.String(),
		CloudflareID: aRecordID,
	}); err != nil {
		s.Logger.Warn("register: upsert A dns_record (non-fatal)", "err", err, "device_id", dev.ID)
	}
	if v6.IsValid() {
		if err := s.DNSRecords.Upsert(ctx, &db.DNSRecord{
			DeviceID:     dev.ID,
			FQDN:         fullName,
			Type:         db.DNSTypeAAAA,
			Value:        v6.String(),
			CloudflareID: aaaaRecordID,
		}); err != nil {
			s.Logger.Warn("register: upsert AAAA dns_record (non-fatal)", "err", err, "device_id", dev.ID)
		}
	}

	writeJSON(w, http.StatusCreated, registerResp{
		AssignedSubdomain:  assigned,
		DeviceJWT:          signed,
		HubCertFingerprint: s.HubCertFingerprint,
	})
}

// bearerToken extracts and returns the raw token from the
// Authorization header. Returns "", false when the header is missing
// or doesn't start with "Bearer ".
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// bestEffortCFDelete logs but never returns an error. Used in the
// rollback paths above where the request is already failing for some
// other reason and we don't want a secondary cleanup error to mask
// the primary one in logs.
func (s *Server) bestEffortCFDelete(ctx context.Context, recordID string) {
	if recordID == "" || s.CFClient == nil {
		return
	}
	if err := s.CFClient.DeleteRecord(ctx, recordID); err != nil {
		s.Logger.Warn("register: cloudflare DeleteRecord rollback failed", "err", err, "cf_record_id", recordID)
	}
}

// bestEffortDeviceDelete removes a device row that was just inserted by
// a failed register attempt. Mirrors bestEffortCFDelete in posture:
// any error is logged, never returned. If the delete fails an admin
// will need to manually drop the row before the same device_id can
// re-enroll.
func (s *Server) bestEffortDeviceDelete(ctx context.Context, deviceID string) {
	if deviceID == "" || s.Devices == nil {
		return
	}
	if err := s.Devices.Delete(ctx, deviceID); err != nil {
		s.Logger.Warn("register: device row rollback failed", "err", err, "device_id", deviceID)
	}
}
