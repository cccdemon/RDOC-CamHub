package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/auth"
	"github.com/raumdock/rdoc-camhub/internal/cloudflare"
	"github.com/raumdock/rdoc-camhub/internal/db"
	"github.com/raumdock/rdoc-camhub/internal/devicejwt"
)

// ---- stubs ----------------------------------------------------------

// stubDevices implements DeviceWriter with an in-memory map. Returns
// db.ErrNotFound for unknown ids so the handler's NotFound checks
// behave realistically.
type stubDevices struct {
	bySub      map[string]*db.Device
	byID       map[string]*db.Device
	createErr  error
	deleteErr  error
	created    []*db.DeviceRegistration
	deleted    []string
}

func newStubDevices() *stubDevices {
	return &stubDevices{
		bySub: map[string]*db.Device{},
		byID:  map[string]*db.Device{},
	}
}

func (s *stubDevices) Create(_ context.Context, reg *db.DeviceRegistration) (*db.Device, error) {
	s.created = append(s.created, reg)
	if s.createErr != nil {
		return nil, s.createErr
	}
	d := &db.Device{
		ID:           reg.ID,
		Name:         reg.Name,
		Subdomain:    reg.Subdomain,
		DeviceJWTKID: reg.DeviceJWTKID,
		PublicIP:     reg.PublicIP,
		PublicIPv6:   reg.PublicIPv6,
		Status:       db.DeviceEnrolled,
		EnrolledAt:   time.Now(),
	}
	s.bySub[reg.Subdomain] = d
	s.byID[reg.ID] = d
	return d, nil
}

func (s *stubDevices) BySubdomain(_ context.Context, sub string) (*db.Device, error) {
	if d, ok := s.bySub[sub]; ok {
		return d, nil
	}
	return nil, db.ErrNotFound
}

func (s *stubDevices) GetByID(_ context.Context, id string) (*db.Device, error) {
	if d, ok := s.byID[id]; ok {
		return d, nil
	}
	return nil, db.ErrNotFound
}

func (s *stubDevices) UpdateHeartbeat(_ context.Context, _ string, _ *db.HeartbeatUpdate) (time.Time, error) {
	return time.Now(), nil
}

func (s *stubDevices) Delete(_ context.Context, id string) error {
	s.deleted = append(s.deleted, id)
	if s.deleteErr != nil {
		return s.deleteErr
	}
	if d, ok := s.byID[id]; ok {
		delete(s.byID, id)
		delete(s.bySub, d.Subdomain)
	}
	return nil
}

// stubDNSRecords records Upsert calls. Get returns ErrNotFound since
// the register handler doesn't read records back.
type stubDNSRecords struct {
	upserted []*db.DNSRecord
	err      error
}

func (s *stubDNSRecords) Upsert(_ context.Context, r *db.DNSRecord) error {
	if s.err != nil {
		return s.err
	}
	s.upserted = append(s.upserted, r)
	return nil
}

func (s *stubDNSRecords) Get(_ context.Context, _ string, _ db.DNSRecordType) (*db.DNSRecord, error) {
	return nil, db.ErrNotFound
}

// stubSigner satisfies DeviceJWTSigner with a deterministic kid and a
// canned token string (so tests can assert on it without re-verifying
// real Ed25519 signatures). Verify is keyed by exact token-string match
// against verifyMap so heartbeat tests can inject "this token resolves
// to these claims".
type stubSigner struct {
	kid       string
	token     string
	err       error
	lastCl    devicejwt.Claims
	verifyMap map[string]*devicejwt.Claims
	verifyErr error
}

func (s *stubSigner) Sign(c devicejwt.Claims) (string, error) {
	s.lastCl = c
	if s.err != nil {
		return "", s.err
	}
	return s.token, nil
}
func (s *stubSigner) Verify(tok string) (*devicejwt.Claims, error) {
	if s.verifyErr != nil {
		return nil, s.verifyErr
	}
	if c, ok := s.verifyMap[tok]; ok {
		return c, nil
	}
	return nil, devicejwt.ErrInvalidToken
}
func (s *stubSigner) SigningKID() string { return s.kid }

// stubCF satisfies cloudflare.DNSClient. Tracks call ordering so tests
// can assert rollback delete-on-failure paths.
type stubCF struct {
	createErrA    error // returned on the first CreateRecord (A) call
	createErrAAAA error // returned on the second CreateRecord (AAAA) call
	createIdx     int
	updateErr     error // returned on every UpdateRecord call

	created []recordCall
	updated []recordCall
	deleted []string
}

type recordCall struct {
	FQDN     string
	Type     cloudflare.RecordType
	Value    string
	RecordID string
}

func (s *stubCF) CreateRecord(_ context.Context, fqdn string, rt cloudflare.RecordType, value string) (string, error) {
	idx := s.createIdx
	s.createIdx++
	switch idx {
	case 0:
		if s.createErrA != nil {
			return "", s.createErrA
		}
	case 1:
		if s.createErrAAAA != nil {
			return "", s.createErrAAAA
		}
	}
	id := "cf-record-" + strings.ToLower(string(rt))
	s.created = append(s.created, recordCall{FQDN: fqdn, Type: rt, Value: value, RecordID: id})
	return id, nil
}

func (s *stubCF) UpdateRecord(_ context.Context, recordID, fqdn string, rt cloudflare.RecordType, value string) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.updated = append(s.updated, recordCall{FQDN: fqdn, Type: rt, Value: value, RecordID: recordID})
	return nil
}

func (s *stubCF) DeleteRecord(_ context.Context, recordID string) error {
	s.deleted = append(s.deleted, recordID)
	return nil
}

// ---- harness --------------------------------------------------------

type registerHarness struct {
	srv     *Server
	tokens  *stubEnrollmentTokens
	devices *stubDevices
	dns     *stubDNSRecords
	signer  *stubSigner
	cf      *stubCF
}

func newRegisterHarness(t *testing.T) *registerHarness {
	t.Helper()
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})

	h := &registerHarness{
		srv:     srv,
		tokens:  &stubEnrollmentTokens{},
		devices: newStubDevices(),
		dns:     &stubDNSRecords{},
		signer:  &stubSigner{kid: "kid-test", token: "signed-jwt-test"},
		cf:      &stubCF{},
	}
	srv.EnrollmentTokens = h.tokens
	srv.Devices = h.devices
	srv.DNSRecords = h.dns
	srv.DeviceJWT = h.signer
	srv.CFClient = h.cf
	srv.ParentDomain = "raumdock.org"
	srv.HubCertFingerprint = "fp-test"
	return h
}

func validRegisterBody(t *testing.T, deviceID, name string) []byte {
	t.Helper()
	body := registerReq{
		DeviceID:      deviceID,
		PreferredName: name,
		PublicIP:      "192.0.2.10",
		Ports:         json.RawMessage(`{"webrtc":443}`),
		Capabilities:  json.RawMessage(`{"model":"C920"}`),
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func doRegister(t *testing.T, h *registerHarness, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/register", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.srv.registerDevice(rec, req)
	return rec
}

// ---- tests ----------------------------------------------------------

func TestRegister_HappyPath(t *testing.T) {
	h := newRegisterHarness(t)
	rec := doRegister(t, h, "raw-token-123", validRegisterBody(t, "cam-001", "livingroom"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201 (body=%q)", rec.Code, rec.Body.String())
	}
	var resp registerResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AssignedSubdomain != "livingroom" {
		t.Errorf("subdomain: got %q, want livingroom", resp.AssignedSubdomain)
	}
	if resp.DeviceJWT != "signed-jwt-test" {
		t.Errorf("jwt: got %q, want signed-jwt-test", resp.DeviceJWT)
	}
	if resp.HubCertFingerprint != "fp-test" {
		t.Errorf("fingerprint: got %q, want fp-test", resp.HubCertFingerprint)
	}

	// Token consumed with the right hash + device id.
	if h.tokens.consumedHash != auth.HashEnrollmentToken("raw-token-123") {
		t.Errorf("consumed hash mismatch")
	}
	if h.tokens.consumedDeviceID != "cam-001" {
		t.Errorf("consumed device_id: got %q, want cam-001", h.tokens.consumedDeviceID)
	}

	// Cloudflare: one A record created.
	if len(h.cf.created) != 1 {
		t.Fatalf("cf.created: got %d, want 1 (A only, no v6 in body)", len(h.cf.created))
	}
	if h.cf.created[0].FQDN != "livingroom.raumdock.org" {
		t.Errorf("fqdn: got %q", h.cf.created[0].FQDN)
	}
	if h.cf.created[0].Type != cloudflare.TypeA {
		t.Errorf("type: got %v, want A", h.cf.created[0].Type)
	}

	// Device row + DNS pointer persisted.
	if len(h.devices.created) != 1 || h.devices.created[0].Subdomain != "livingroom" {
		t.Errorf("devices.created: %+v", h.devices.created)
	}
	if h.devices.created[0].DeviceJWTKID != "kid-test" {
		t.Errorf("kid persisted: got %q, want kid-test", h.devices.created[0].DeviceJWTKID)
	}
	if len(h.dns.upserted) != 1 || h.dns.upserted[0].Type != db.DNSTypeA {
		t.Errorf("dns.upserted: %+v", h.dns.upserted)
	}

	// Signer received the right claims.
	if h.signer.lastCl.DeviceID != "cam-001" || h.signer.lastCl.Subdomain != "livingroom" {
		t.Errorf("signer claims: %+v", h.signer.lastCl)
	}
}

func TestRegister_WithIPv6_CreatesBothRecords(t *testing.T) {
	h := newRegisterHarness(t)

	body := registerReq{
		DeviceID:      "cam-002",
		PreferredName: "bedroom",
		PublicIP:      "192.0.2.20",
		PublicIPv6:    "2001:db8::1",
	}
	raw, _ := json.Marshal(body)

	rec := doRegister(t, h, "raw-token-456", raw)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201 (body=%q)", rec.Code, rec.Body.String())
	}
	if len(h.cf.created) != 2 {
		t.Fatalf("cf.created: got %d, want 2 (A + AAAA)", len(h.cf.created))
	}
	if h.cf.created[1].Type != cloudflare.TypeAAAA || h.cf.created[1].Value != "2001:db8::1" {
		t.Errorf("AAAA record: %+v", h.cf.created[1])
	}
	if len(h.dns.upserted) != 2 {
		t.Errorf("dns.upserted should have 2 (A + AAAA), got %d", len(h.dns.upserted))
	}
}

func TestRegister_NoBearer_401(t *testing.T) {
	h := newRegisterHarness(t)
	rec := doRegister(t, h, "", validRegisterBody(t, "cam-001", "livingroom"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if h.tokens.consumedHash != "" {
		t.Error("token consume must not be called without a bearer")
	}
}

func TestRegister_TokenUnusable_401(t *testing.T) {
	h := newRegisterHarness(t)
	h.tokens.consumeErr = db.ErrNotFound // unknown/consumed/expired

	rec := doRegister(t, h, "raw-token-xxx", validRegisterBody(t, "cam-001", "livingroom"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 (body=%q)", rec.Code, rec.Body.String())
	}
	// No side effects past the token consume attempt.
	if len(h.cf.created) != 0 {
		t.Error("CF must not be called when token is unusable")
	}
	if len(h.devices.created) != 0 {
		t.Error("device row must not be created when token is unusable")
	}
}

func TestRegister_ReservedName_400(t *testing.T) {
	h := newRegisterHarness(t)
	rec := doRegister(t, h, "tok", validRegisterBody(t, "cam-001", "api"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400 (body=%q)", rec.Code, rec.Body.String())
	}
	// Token must NOT be consumed for a reserved-name reject — the cam
	// can retry with a different name.
	if h.tokens.consumedHash != "" {
		t.Error("reserved-name should reject BEFORE token consume")
	}
}

func TestRegister_InvalidLabelFormat_400(t *testing.T) {
	for _, name := range []string{
		"UPPERCASE", // not all-lowercase
		"-leading",  // leading hyphen
		"trailing-", // trailing hyphen
		"has_underscore",
		"has.dot",
		"way-too-long-" + strings.Repeat("x", 60),
	} {
		t.Run(name, func(t *testing.T) {
			h := newRegisterHarness(t)
			rec := doRegister(t, h, "tok", validRegisterBody(t, "cam-001", name))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status: got %d, want 400", rec.Code)
			}
		})
	}
}

func TestRegister_SubdomainCollision_AssignsSuffix(t *testing.T) {
	h := newRegisterHarness(t)
	// Pre-populate two existing devices with conflicting subdomains.
	h.devices.bySub["livingroom"] = &db.Device{Subdomain: "livingroom"}
	h.devices.bySub["livingroom-2"] = &db.Device{Subdomain: "livingroom-2"}

	rec := doRegister(t, h, "tok", validRegisterBody(t, "cam-003", "livingroom"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201", rec.Code)
	}
	var resp registerResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.AssignedSubdomain != "livingroom-3" {
		t.Errorf("subdomain: got %q, want livingroom-3", resp.AssignedSubdomain)
	}
	if h.cf.created[0].FQDN != "livingroom-3.raumdock.org" {
		t.Errorf("CF fqdn should use assigned subdomain: %q", h.cf.created[0].FQDN)
	}
}

func TestRegister_BadIPv4_400(t *testing.T) {
	h := newRegisterHarness(t)
	body := registerReq{DeviceID: "cam-001", PreferredName: "livingroom", PublicIP: "not-an-ip"}
	raw, _ := json.Marshal(body)
	rec := doRegister(t, h, "tok", raw)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

func TestRegister_BadIPv6_400(t *testing.T) {
	h := newRegisterHarness(t)
	body := registerReq{
		DeviceID:      "cam-001",
		PreferredName: "livingroom",
		PublicIP:      "192.0.2.10",
		PublicIPv6:    "::ffff:192.0.2.10", // IPv4-mapped, rejected by Is4In6 check
	}
	raw, _ := json.Marshal(body)
	rec := doRegister(t, h, "tok", raw)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

func TestRegister_CFCreateAFails_TokenAlreadyConsumed_502(t *testing.T) {
	h := newRegisterHarness(t)
	h.cf.createErrA = errors.New("cloudflare 500")

	rec := doRegister(t, h, "tok", validRegisterBody(t, "cam-001", "livingroom"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502", rec.Code)
	}
	// Per Plan §4.1 token MUST be consumed by this point.
	if h.tokens.consumedHash == "" {
		t.Error("token must have been consumed before CF call")
	}
	// No device row created.
	if len(h.devices.created) != 0 {
		t.Errorf("no device row should exist on CF failure; got %d", len(h.devices.created))
	}
}

func TestRegister_CFCreateAAAAFails_RollsBackA(t *testing.T) {
	h := newRegisterHarness(t)
	h.cf.createErrAAAA = errors.New("cloudflare 500 on AAAA")

	body := registerReq{
		DeviceID:      "cam-001",
		PreferredName: "livingroom",
		PublicIP:      "192.0.2.10",
		PublicIPv6:    "2001:db8::1",
	}
	raw, _ := json.Marshal(body)

	rec := doRegister(t, h, "tok", raw)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502", rec.Code)
	}
	// The A record we just created must be cleaned up.
	if len(h.cf.deleted) != 1 || h.cf.deleted[0] != "cf-record-a" {
		t.Errorf("expected A record cleanup; got deleted=%v", h.cf.deleted)
	}
}

func TestRegister_DeviceCreateFails_RollsBackCF(t *testing.T) {
	h := newRegisterHarness(t)
	h.devices.createErr = errors.New("unique violation")

	rec := doRegister(t, h, "tok", validRegisterBody(t, "cam-001", "livingroom"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
	if len(h.cf.deleted) != 1 || h.cf.deleted[0] != "cf-record-a" {
		t.Errorf("CF A record must be cleaned up on device insert failure; deleted=%v", h.cf.deleted)
	}
}

func TestRegister_SignFails_RollsBackEverything(t *testing.T) {
	h := newRegisterHarness(t)
	h.signer.err = errors.New("kid missing private")

	rec := doRegister(t, h, "tok", validRegisterBody(t, "cam-001", "livingroom"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
	// Both the device row AND the CF A record must be rolled back.
	if len(h.devices.deleted) != 1 || h.devices.deleted[0] != "cam-001" {
		t.Errorf("device row not rolled back: %v", h.devices.deleted)
	}
	if len(h.cf.deleted) != 1 || h.cf.deleted[0] != "cf-record-a" {
		t.Errorf("CF A record not rolled back: %v", h.cf.deleted)
	}
}

func TestRegister_NotConfigured_503(t *testing.T) {
	// Default Server (newTestServer) has no DeviceJWT/CFClient/ParentDomain.
	srv := newTestServer(t, &stubUsers{}, &stubSessions{})

	req := httptest.NewRequest(http.MethodPost, "/v1/devices/register", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.registerDevice(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", rec.Code)
	}
}

func TestRegister_BodyTooLarge_413(t *testing.T) {
	h := newRegisterHarness(t)
	// 32 KiB body — well over registerMaxBody (16 KiB).
	junk := strings.Repeat("x", 32*1024)
	body := []byte(`{"capabilities":{"junk":"` + junk + `"}}`)
	rec := doRegister(t, h, "tok", body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: got %d, want 413", rec.Code)
	}
}
