package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/cloudflare"
	"github.com/raumdock/rdoc-camhub/internal/db"
	"github.com/raumdock/rdoc-camhub/internal/devicejwt"
)

// stubDevices is shared with devices_register_test.go but doesn't track
// UpdateHeartbeat calls. Extend it here for heartbeat assertions.
type heartbeatRecord struct {
	DeviceID     string
	PublicIP     netip.Addr
	PublicIPv6   netip.Addr
	StreamHealth string
	CamVersion   string
}

// trackingDevices wraps stubDevices to record UpdateHeartbeat args.
// We do this via composition rather than extending stubDevices itself
// so existing register tests stay untouched.
type trackingDevices struct {
	*stubDevices
	heartbeats     []heartbeatRecord
	heartbeatErr   error
}

func (t *trackingDevices) UpdateHeartbeat(_ context.Context, id string, h *db.HeartbeatUpdate) (time.Time, error) {
	if t.heartbeatErr != nil {
		return time.Time{}, t.heartbeatErr
	}
	t.heartbeats = append(t.heartbeats, heartbeatRecord{
		DeviceID:     id,
		PublicIP:     h.PublicIP,
		PublicIPv6:   h.PublicIPv6,
		StreamHealth: h.StreamHealth,
		CamVersion:   h.CamVersion,
	})
	return time.Now(), nil
}

// trackingDNS wraps stubDNSRecords with a Get backed by an in-memory map
// so the heartbeat handler can look up existing records.
type trackingDNS struct {
	*stubDNSRecords
	byKey  map[string]*db.DNSRecord // key: deviceID + "|" + type
	getErr error
}

func newTrackingDNS() *trackingDNS {
	return &trackingDNS{
		stubDNSRecords: &stubDNSRecords{},
		byKey:          map[string]*db.DNSRecord{},
	}
}

func (t *trackingDNS) Get(_ context.Context, deviceID string, ty db.DNSRecordType) (*db.DNSRecord, error) {
	if t.getErr != nil {
		return nil, t.getErr
	}
	if r, ok := t.byKey[deviceID+"|"+string(ty)]; ok {
		return r, nil
	}
	return nil, db.ErrNotFound
}

// heartbeatHarness wires the heartbeat handler with all collaborators.
type heartbeatHarness struct {
	srv     *Server
	devices *trackingDevices
	dns     *trackingDNS
	signer  *stubSigner
	cf      *stubCF
}

func newHeartbeatHarness(t *testing.T) *heartbeatHarness {
	t.Helper()
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})
	h := &heartbeatHarness{
		srv:     srv,
		devices: &trackingDevices{stubDevices: newStubDevices()},
		dns:     newTrackingDNS(),
		signer:  &stubSigner{kid: "kid-test", verifyMap: map[string]*devicejwt.Claims{}},
		cf:      &stubCF{},
	}
	srv.EnrollmentTokens = &stubEnrollmentTokens{}
	srv.Devices = h.devices
	srv.DNSRecords = h.dns
	srv.DeviceJWT = h.signer
	srv.CFClient = h.cf
	srv.ParentDomain = "raumdock.org"
	return h
}

// addDevice inserts a row into the harness's device map and pre-loads
// a verifyMap entry so the JWT "valid-token-<id>" maps to claims for it.
func (h *heartbeatHarness) addDevice(t *testing.T, id, sub, v4, v6 string) {
	t.Helper()
	d := &db.Device{ID: id, Subdomain: sub}
	if v4 != "" {
		d.PublicIP = netip.MustParseAddr(v4)
	}
	if v6 != "" {
		d.PublicIPv6 = netip.MustParseAddr(v6)
	}
	h.devices.byID[id] = d
	h.devices.bySub[sub] = d
	h.signer.verifyMap["valid-token-"+id] = &devicejwt.Claims{
		DeviceID:  id,
		Subdomain: sub,
	}
}

func doHeartbeat(t *testing.T, h *heartbeatHarness, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/heartbeat", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.srv.heartbeatDevice(rec, req)
	return rec
}

// ---- tests ----------------------------------------------------------

func TestHeartbeat_HappyPath_NoIPChange_204(t *testing.T) {
	h := newHeartbeatHarness(t)
	h.addDevice(t, "cam-001", "livingroom", "192.0.2.10", "")

	body, _ := json.Marshal(heartbeatReq{PublicIP: "192.0.2.10", StreamHealth: "healthy", Version: "1.2.3"})
	rec := doHeartbeat(t, h, "valid-token-cam-001", body)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204 (body=%q)", rec.Code, rec.Body.String())
	}
	if len(h.devices.heartbeats) != 1 {
		t.Fatalf("UpdateHeartbeat calls: got %d, want 1", len(h.devices.heartbeats))
	}
	hb := h.devices.heartbeats[0]
	if hb.DeviceID != "cam-001" || hb.StreamHealth != "healthy" || hb.CamVersion != "1.2.3" {
		t.Errorf("hb fields: %+v", hb)
	}
	// IP unchanged → no CF call.
	if len(h.cf.created) != 0 || len(h.cf.updated) != 0 {
		t.Errorf("CF should not be touched when IP unchanged; created=%d updated=%d", len(h.cf.created), len(h.cf.updated))
	}
}

func TestHeartbeat_IPv4Changed_UpdatesCloudflare(t *testing.T) {
	h := newHeartbeatHarness(t)
	h.addDevice(t, "cam-001", "livingroom", "192.0.2.10", "")
	// Pre-load dns_records so the handler does UpdateRecord (not Create).
	h.dns.byKey["cam-001|A"] = &db.DNSRecord{
		DeviceID:     "cam-001",
		FQDN:         "livingroom.raumdock.org",
		Type:         db.DNSTypeA,
		Value:        "192.0.2.10",
		CloudflareID: "cf-existing-a",
	}

	body, _ := json.Marshal(heartbeatReq{PublicIP: "192.0.2.99"})
	rec := doHeartbeat(t, h, "valid-token-cam-001", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204", rec.Code)
	}

	if len(h.cf.updated) != 1 {
		t.Fatalf("CF UpdateRecord calls: got %d, want 1", len(h.cf.updated))
	}
	u := h.cf.updated[0]
	if u.RecordID != "cf-existing-a" || u.Value != "192.0.2.99" || u.Type != cloudflare.TypeA {
		t.Errorf("CF update args wrong: %+v", u)
	}
}

func TestHeartbeat_IPv6Added_CreatesAAAARecord(t *testing.T) {
	h := newHeartbeatHarness(t)
	h.addDevice(t, "cam-001", "livingroom", "192.0.2.10", "")
	// No AAAA in dns_records → handler should CREATE.

	body, _ := json.Marshal(heartbeatReq{
		PublicIP:   "192.0.2.10",       // unchanged
		PublicIPv6: "2001:db8::42",     // newly added
	})
	rec := doHeartbeat(t, h, "valid-token-cam-001", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204", rec.Code)
	}
	if len(h.cf.created) != 1 {
		t.Fatalf("CF CreateRecord calls: got %d, want 1 (AAAA only)", len(h.cf.created))
	}
	if h.cf.created[0].Type != cloudflare.TypeAAAA || h.cf.created[0].Value != "2001:db8::42" {
		t.Errorf("AAAA create wrong: %+v", h.cf.created[0])
	}
}

func TestHeartbeat_IPv6Dropped_KeepsRecord(t *testing.T) {
	h := newHeartbeatHarness(t)
	h.addDevice(t, "cam-001", "livingroom", "192.0.2.10", "2001:db8::1")
	h.dns.byKey["cam-001|AAAA"] = &db.DNSRecord{
		DeviceID:     "cam-001",
		Type:         db.DNSTypeAAAA,
		Value:        "2001:db8::1",
		CloudflareID: "cf-existing-aaaa",
	}

	// Cam reports no IPv6 this beat. Handler should NOT delete or
	// update the AAAA record — IPv6 flaps and we'd prefer stable DNS.
	body, _ := json.Marshal(heartbeatReq{PublicIP: "192.0.2.10"})
	rec := doHeartbeat(t, h, "valid-token-cam-001", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204", rec.Code)
	}
	if len(h.cf.updated) != 0 || len(h.cf.deleted) != 0 {
		t.Errorf("AAAA record must not change on IPv6 absence; updated=%v deleted=%v", h.cf.updated, h.cf.deleted)
	}
}

func TestHeartbeat_NoBearer_401(t *testing.T) {
	h := newHeartbeatHarness(t)
	body, _ := json.Marshal(heartbeatReq{PublicIP: "192.0.2.10"})
	rec := doHeartbeat(t, h, "", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
}

func TestHeartbeat_InvalidJWT_401(t *testing.T) {
	h := newHeartbeatHarness(t)
	// "garbage" doesn't appear in verifyMap → stub returns ErrInvalidToken.
	body, _ := json.Marshal(heartbeatReq{PublicIP: "192.0.2.10"})
	rec := doHeartbeat(t, h, "garbage", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
}

// Unknown device (JWT claims an id that no longer exists) collapses to
// 401, not 404. Pins the no-oracle invariant.
func TestHeartbeat_UnknownDevice_401(t *testing.T) {
	h := newHeartbeatHarness(t)
	// Add a verify map entry but NO device row.
	h.signer.verifyMap["orphan-token"] = &devicejwt.Claims{DeviceID: "cam-ghost", Subdomain: "ghost"}

	body, _ := json.Marshal(heartbeatReq{PublicIP: "192.0.2.10"})
	rec := doHeartbeat(t, h, "orphan-token", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 (no oracle)", rec.Code)
	}
}

// Subdomain claim disagrees with current row. Refuse — we don't yet
// support cam renames and the divergence is suspicious.
func TestHeartbeat_SubdomainMismatch_401(t *testing.T) {
	h := newHeartbeatHarness(t)
	h.addDevice(t, "cam-001", "livingroom", "192.0.2.10", "")
	// Override the claim to a stale subdomain.
	h.signer.verifyMap["stale-claim"] = &devicejwt.Claims{
		DeviceID:  "cam-001",
		Subdomain: "old-name",
	}

	body, _ := json.Marshal(heartbeatReq{PublicIP: "192.0.2.10"})
	rec := doHeartbeat(t, h, "stale-claim", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if len(h.devices.heartbeats) != 0 {
		t.Error("UpdateHeartbeat must not run on subdomain mismatch")
	}
}

func TestHeartbeat_BadIPv4_400(t *testing.T) {
	h := newHeartbeatHarness(t)
	h.addDevice(t, "cam-001", "livingroom", "192.0.2.10", "")

	body, _ := json.Marshal(heartbeatReq{PublicIP: "not-an-ip"})
	rec := doHeartbeat(t, h, "valid-token-cam-001", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

// CF UpdateRecord failure during heartbeat must NOT fail the heartbeat
// itself — the cam needs liveness confirmation regardless. dns_records
// stays at the old value (the CF record is still at the old value too).
func TestHeartbeat_CFUpdateFails_Returns204(t *testing.T) {
	h := newHeartbeatHarness(t)
	h.addDevice(t, "cam-001", "livingroom", "192.0.2.10", "")
	h.dns.byKey["cam-001|A"] = &db.DNSRecord{
		DeviceID: "cam-001", Type: db.DNSTypeA, Value: "192.0.2.10", CloudflareID: "cf-existing-a",
	}
	h.cf.updateErr = errors.New("cloudflare 500 on update")

	body, _ := json.Marshal(heartbeatReq{PublicIP: "192.0.2.99"})
	rec := doHeartbeat(t, h, "valid-token-cam-001", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204 (heartbeat should not fail on CF error)", rec.Code)
	}
	// dns_records.Upsert should NOT have been called — the CF update
	// failed, so the local view stays consistent with what's actually
	// in Cloudflare.
	if len(h.dns.upserted) != 0 {
		t.Errorf("dns_records must not be upserted when CF UpdateRecord failed; got %d", len(h.dns.upserted))
	}
}

func TestHeartbeat_CombinesStatusIntoStreamHealth(t *testing.T) {
	h := newHeartbeatHarness(t)
	h.addDevice(t, "cam-001", "livingroom", "192.0.2.10", "")

	body, _ := json.Marshal(heartbeatReq{
		PublicIP:     "192.0.2.10",
		Status:       "streaming",
		StreamHealth: "healthy",
	})
	rec := doHeartbeat(t, h, "valid-token-cam-001", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204", rec.Code)
	}
	if got := h.devices.heartbeats[0].StreamHealth; got != "streaming · healthy" {
		t.Errorf("stream_health combine: got %q, want 'streaming · healthy'", got)
	}
}

func TestHeartbeat_NotConfigured_503(t *testing.T) {
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})
	body, _ := json.Marshal(heartbeatReq{PublicIP: "192.0.2.10"})
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/heartbeat", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.heartbeatDevice(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", rec.Code)
	}
}

func TestHeartbeat_BodyTooLarge_413(t *testing.T) {
	h := newHeartbeatHarness(t)
	h.addDevice(t, "cam-001", "livingroom", "192.0.2.10", "")
	junk := strings.Repeat("x", 16*1024)
	body := []byte(`{"version":"` + junk + `"}`)
	rec := doHeartbeat(t, h, "valid-token-cam-001", body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: got %d, want 413", rec.Code)
	}
}

