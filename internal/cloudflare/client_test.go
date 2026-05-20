package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newFakeCF returns an httptest.Server whose handler the test supplies.
// Plus a Client preconfigured to talk to it with a fixed token + zone.
func newFakeCF(t *testing.T, h http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{
		APIToken: "test-token",
		ZoneID:   "zone123",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, c
}

func envelope(success bool, id string) []byte {
	out := map[string]any{
		"success": success,
		"errors":  []any{},
		"result":  map[string]any{"id": id, "name": "ignored.example.com"},
	}
	b, _ := json.Marshal(out)
	return b
}

func TestNew_RequiresTokenAndZone(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no token", Config{ZoneID: "z"}},
		{"no zone", Config{APIToken: "t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("New(%+v) should have errored", tc.cfg)
			}
		})
	}
}

func TestCreateRecord_HappyPath(t *testing.T) {
	var (
		gotMethod, gotPath, gotAuth, gotCT string
		gotBody                            recordRequest
	)
	_, c := newFakeCF(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelope(true, "rec-abc"))
	})

	id, err := c.CreateRecord(context.Background(), "livingroom.raumdock.org", TypeA, "192.0.2.10")
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	if id != "rec-abc" {
		t.Errorf("id: got %q, want %q", id, "rec-abc")
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotPath != "/zones/zone123/dns_records" {
		t.Errorf("path: got %q", gotPath)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("auth header: got %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type: got %q", gotCT)
	}
	if gotBody.Type != TypeA || gotBody.Name != "livingroom.raumdock.org" || gotBody.Content != "192.0.2.10" {
		t.Errorf("request body: %+v", gotBody)
	}
	if gotBody.TTL != DefaultRecordTTL {
		t.Errorf("TTL: got %d, want %d", gotBody.TTL, DefaultRecordTTL)
	}
	if gotBody.Proxied {
		t.Error("Proxied must be false — CamHub does not proxy streams")
	}
}

func TestCreateRecord_APIErrorSurfaces(t *testing.T) {
	_, c := newFakeCF(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1004,"message":"DNS Validation Error"}],"result":null}`))
	})

	_, err := c.CreateRecord(context.Background(), "bad.example.com", TypeA, "not-an-ip")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", apiErr.StatusCode)
	}
	if len(apiErr.Errors) != 1 || apiErr.Errors[0].Code != 1004 {
		t.Errorf("error envelope not preserved: %+v", apiErr.Errors)
	}
	// The Error() string should be diagnostic enough to grep logs.
	if !strings.Contains(apiErr.Error(), "1004") || !strings.Contains(apiErr.Error(), "DNS Validation Error") {
		t.Errorf("Error() lacks key fields: %q", apiErr.Error())
	}
}

// 200 with success=false is a documented Cloudflare quirk for partial
// failures (e.g. on bulk endpoints). It must be treated as failure.
func TestCreateRecord_200ButSuccessFalse(t *testing.T) {
	_, c := newFakeCF(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":81044,"message":"quota"}],"result":null}`))
	})

	_, err := c.CreateRecord(context.Background(), "x.example.com", TypeA, "1.2.3.4")
	if err == nil {
		t.Fatal("expected error on 200/success=false, got nil")
	}
}

// A non-JSON response (HTML error page from an intermediary, truncated
// body) must NOT panic and must produce a diagnostic error.
func TestCreateRecord_NonJSONBody(t *testing.T) {
	_, c := newFakeCF(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
	})

	_, err := c.CreateRecord(context.Background(), "x.example.com", TypeA, "1.2.3.4")
	if err == nil {
		t.Fatal("expected error on non-JSON body, got nil")
	}
	if !strings.Contains(err.Error(), "non-JSON") {
		t.Errorf("error should mention non-JSON body, got: %v", err)
	}
}

func TestUpdateRecord_HappyPath(t *testing.T) {
	var gotMethod, gotPath string
	_, c := newFakeCF(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelope(true, "rec-abc"))
	})

	if err := c.UpdateRecord(context.Background(), "rec-abc", "livingroom.raumdock.org", TypeAAAA, "2001:db8::1"); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method: got %q, want PUT", gotMethod)
	}
	if gotPath != "/zones/zone123/dns_records/rec-abc" {
		t.Errorf("path: got %q", gotPath)
	}
}

func TestDeleteRecord_HappyPath(t *testing.T) {
	var gotMethod, gotPath string
	_, c := newFakeCF(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelope(true, "rec-abc"))
	})

	if err := c.DeleteRecord(context.Background(), "rec-abc"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method: got %q, want DELETE", gotMethod)
	}
	if gotPath != "/zones/zone123/dns_records/rec-abc" {
		t.Errorf("path: got %q", gotPath)
	}
}

// A record id with URL-unsafe characters must be path-escaped so a
// stray slash can't pivot the request to a different endpoint.
func TestRecordID_PathEscaped(t *testing.T) {
	var gotPath string
	_, c := newFakeCF(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelope(true, "x"))
	})

	if err := c.DeleteRecord(context.Background(), "weird/id with spaces"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	// url.PathEscape encodes '/' as %2F and ' ' as %20.
	if !strings.Contains(gotPath, "weird%2Fid%20with%20spaces") {
		t.Errorf("record id wasn't path-escaped; got path=%q", gotPath)
	}
}

// An empty id on Create (Cloudflare returns success=true but no id)
// surfaces as an error — otherwise we'd write a useless row to
// dns_records.
func TestCreateRecord_EmptyIDIsError(t *testing.T) {
	_, c := newFakeCF(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"","name":""}}`))
	})

	if _, err := c.CreateRecord(context.Background(), "x.example.com", TypeA, "1.2.3.4"); err == nil {
		t.Fatal("expected error when CF returns empty id, got nil")
	}
}
