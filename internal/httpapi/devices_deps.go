package httpapi

import (
	"context"
	"time"

	"github.com/raumdock/rdoc-camhub/internal/cloudflare"
	"github.com/raumdock/rdoc-camhub/internal/db"
	"github.com/raumdock/rdoc-camhub/internal/devicejwt"
)

// The interfaces below are the device-register / heartbeat handlers'
// dependencies. Each one is the narrowest slice of its concrete store
// (or external client) that the handler actually uses. Keeping them
// here in one file makes it obvious which collaborators the device
// path needs and lets a single test stub satisfy all of them.

// DeviceWriter is the device-store surface the handlers depend on.
// *db.DeviceStore satisfies it.
type DeviceWriter interface {
	Create(ctx context.Context, reg *db.DeviceRegistration) (*db.Device, error)
	BySubdomain(ctx context.Context, sub string) (*db.Device, error)
	GetByID(ctx context.Context, id string) (*db.Device, error)
	UpdateHeartbeat(ctx context.Context, id string, h *db.HeartbeatUpdate) (time.Time, error)
	Delete(ctx context.Context, id string) error
}

// DNSRecordWriter is the dns_records-store surface. *db.DNSRecordStore
// satisfies it.
type DNSRecordWriter interface {
	Upsert(ctx context.Context, r *db.DNSRecord) error
	Get(ctx context.Context, deviceID string, t db.DNSRecordType) (*db.DNSRecord, error)
}

// DeviceJWTSigner is what we need from the device-JWT ring.
// *devicejwt.Ring satisfies it.
//
// SigningKID returns the kid the ring will use for the next Sign call;
// we persist it on the device row so the retirement-window code in M4
// can target devices still bound to an old kid.
type DeviceJWTSigner interface {
	Sign(c devicejwt.Claims) (string, error)
	SigningKID() string
}

// DNSClient mirrors cloudflare.DNSClient so handlers and tests can
// stub it without importing the cloudflare package directly. The
// canonical type lives in the cloudflare package; this re-export
// avoids forcing every test file to import it.
type DNSClient = cloudflare.DNSClient
