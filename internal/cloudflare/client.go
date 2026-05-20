// Package cloudflare is a minimal client for the Cloudflare v4 DNS API,
// scoped to exactly what CamHub needs (Plan §3): create A/AAAA records
// on device enrollment and update them on heartbeat when a cam's public
// IP changes.
//
// We hand-roll the HTTP rather than pull github.com/cloudflare/cloudflare-go
// for two reasons:
//
//   - The official SDK exports ~150 types we don't touch; pulling it
//     bloats the scratch image and complicates dependency auditing for
//     a tool that holds a Zone:DNS:Edit token.
//   - The DNSClient interface below lets tests inject a fake without
//     standing up the SDK's structured-call boilerplate.
//
// Auth model: a single zone-scoped API token (Zone:DNS:Edit) passed as
// Bearer. Token lives in secrets/cf_api_token; see Caddy/Makefile for
// the prod wiring.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultRecordTTL matches the Plan §3 contract: low TTL so IP changes
// propagate quickly. Cloudflare's minimum for non-enterprise zones is
// 60 s, which is also our chosen value.
const DefaultRecordTTL = 60

// RecordType is the subset of DNS record types CamHub creates. Constants
// match the Cloudflare API strings verbatim so callers can pass them
// through without translation.
type RecordType string

const (
	TypeA    RecordType = "A"
	TypeAAAA RecordType = "AAAA"
)

// DNSClient is what the device-register and heartbeat handlers depend
// on. Kept narrow so tests can fake it without reproducing the full
// Cloudflare API.
type DNSClient interface {
	// CreateRecord creates a new DNS record under the configured zone
	// and returns the Cloudflare-assigned record id. The id must be
	// persisted (in dns_records.cloudflare_id) so future updates and
	// deletes can target the record without a list-search.
	CreateRecord(ctx context.Context, fqdn string, rt RecordType, value string) (recordID string, err error)

	// UpdateRecord overwrites an existing record's value (typically on
	// IP change at heartbeat). fqdn and recordType are sent in the
	// payload because the Cloudflare API requires them on every PUT.
	UpdateRecord(ctx context.Context, recordID, fqdn string, rt RecordType, value string) error

	// DeleteRecord removes a record. Called when a device is deleted
	// to keep DNS clean.
	DeleteRecord(ctx context.Context, recordID string) error
}

// Config is the wiring the HTTP client needs. APIToken authenticates
// every request; ZoneID scopes every URL.
type Config struct {
	APIToken string
	ZoneID   string

	// HTTPClient is optional. Nil = a sane default with a 15-second
	// timeout (Cloudflare's API is usually <300 ms; 15 s buys generous
	// headroom while still failing fast on a wedged proxy).
	HTTPClient *http.Client

	// BaseURL is overrideable for tests pointing at an httptest.Server.
	// Empty = api.cloudflare.com/client/v4.
	BaseURL string
}

// New returns the production-ready HTTP client. It validates that the
// required fields are present so a misconfigured deployment fails at
// startup rather than at first device enrollment.
func New(cfg Config) (*Client, error) {
	if cfg.APIToken == "" {
		return nil, errors.New("cloudflare: APIToken is required")
	}
	if cfg.ZoneID == "" {
		return nil, errors.New("cloudflare: ZoneID is required")
	}
	httpC := cfg.HTTPClient
	if httpC == nil {
		httpC = &http.Client{Timeout: 15 * time.Second}
	}
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	return &Client{
		apiToken: cfg.APIToken,
		zoneID:   cfg.ZoneID,
		http:     httpC,
		baseURL:  strings.TrimRight(base, "/"),
	}, nil
}

// Client is the HTTP-backed DNSClient. Exported (not just the
// interface) so callers can inspect config in tests without a type
// assertion.
type Client struct {
	apiToken string
	zoneID   string
	http     *http.Client
	baseURL  string
}

// recordRequest is the v4 API payload shape for both POST and PUT.
// Proxied=false: CamHub wants direct cam IPs in DNS — Cloudflare's
// proxy would force traffic through Cloudflare and we explicitly
// don't proxy streams (Plan §2).
type recordRequest struct {
	Type    RecordType `json:"type"`
	Name    string     `json:"name"`
	Content string     `json:"content"`
	TTL     int        `json:"ttl"`
	Proxied bool       `json:"proxied"`
}

// recordResult is the success-envelope subset we read back. Cloudflare
// always wraps results in {success, errors, result}; we surface
// `errors` verbatim on failure.
type recordResult struct {
	Success bool   `json:"success"`
	Errors  []apiE `json:"errors"`
	Result  struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
}

type apiE struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *Client) CreateRecord(ctx context.Context, fqdn string, rt RecordType, value string) (string, error) {
	body := recordRequest{Type: rt, Name: fqdn, Content: value, TTL: DefaultRecordTTL, Proxied: false}
	out, err := c.do(ctx, http.MethodPost, c.path("/zones/", c.zoneID, "/dns_records"), body)
	if err != nil {
		return "", err
	}
	if out.Result.ID == "" {
		return "", fmt.Errorf("cloudflare: create %s %s returned empty id", rt, fqdn)
	}
	return out.Result.ID, nil
}

func (c *Client) UpdateRecord(ctx context.Context, recordID, fqdn string, rt RecordType, value string) error {
	body := recordRequest{Type: rt, Name: fqdn, Content: value, TTL: DefaultRecordTTL, Proxied: false}
	_, err := c.do(ctx, http.MethodPut, c.path("/zones/", c.zoneID, "/dns_records/", recordID), body)
	return err
}

func (c *Client) DeleteRecord(ctx context.Context, recordID string) error {
	_, err := c.do(ctx, http.MethodDelete, c.path("/zones/", c.zoneID, "/dns_records/", recordID), nil)
	return err
}

// do is the single HTTP funnel. It builds the request with the right
// auth header, encodes the body, decodes the standard Cloudflare
// envelope, and translates non-2xx + envelope.success=false into
// errors.
func (c *Client) do(ctx context.Context, method, urlStr string, body any) (*recordResult, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, rdr)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: %w", method, urlStr, err)
	}
	defer resp.Body.Close()

	// Cap the response read so a wedged or misrouted proxy returning
	// gigabytes of HTML can't OOM the hub.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	out := &recordResult{}
	if err := json.Unmarshal(raw, out); err != nil {
		// Non-JSON response (HTML error page from an intermediary,
		// truncated body, etc.). Surface the status + first 256 bytes
		// so ops can diagnose.
		preview := raw
		if len(preview) > 256 {
			preview = preview[:256]
		}
		return nil, fmt.Errorf("cloudflare %s %s: status=%d non-JSON body: %q", method, urlStr, resp.StatusCode, preview)
	}

	if !out.Success || resp.StatusCode >= 400 {
		return nil, &APIError{StatusCode: resp.StatusCode, Errors: out.Errors}
	}
	return out, nil
}

// path joins segments with the baseURL, URL-encoding the dynamic parts
// (zone id, record id) so a stray slash or weird character can't break
// the URL.
func (c *Client) path(parts ...string) string {
	var b strings.Builder
	b.WriteString(c.baseURL)
	for _, p := range parts {
		// Detect static-looking segments (leading '/') vs dynamic ids.
		// Static segments are written verbatim; ids get path-escaped.
		if strings.HasPrefix(p, "/") {
			b.WriteString(p)
		} else {
			b.WriteString(url.PathEscape(p))
		}
	}
	return b.String()
}

// APIError carries the Cloudflare error envelope. Exported so callers
// can detect specific failure modes (e.g. 401 = bad token) without
// string-matching.
type APIError struct {
	StatusCode int
	Errors     []apiE
}

func (e *APIError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("cloudflare API error: HTTP %d (no body)", e.StatusCode)
	}
	parts := make([]string, 0, len(e.Errors))
	for _, x := range e.Errors {
		parts = append(parts, fmt.Sprintf("code=%d msg=%q", x.Code, x.Message))
	}
	return fmt.Sprintf("cloudflare API error: HTTP %d %s", e.StatusCode, strings.Join(parts, "; "))
}
