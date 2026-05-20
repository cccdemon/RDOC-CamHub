package httpapi

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/raumdock/rdoc-camhub/internal/cloudflare"
	"github.com/raumdock/rdoc-camhub/internal/db"
)

// subdomainLabel is the RFC 1035 LDH ("letters, digits, hyphen") rule
// for a single DNS label, with our additional constraint that the
// label may not start or end with a hyphen. 1–63 characters.
//
// We do NOT allow underscores: most resolvers tolerate them in TXT-flavoured
// records but A/AAAA labels are stricter, and CamHub creates A/AAAA.
var subdomainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ErrSubdomainInvalid is returned by validateSubdomain when the cam's
// preferred_name violates the label rule.
var ErrSubdomainInvalid = errors.New("subdomain: must be 1–63 lowercase LDH characters and not start/end with '-'")

// ErrSubdomainReserved is returned when the preferred name matches the
// hub's reserved list (cloudflare.IsReserved).
var ErrSubdomainReserved = errors.New("subdomain: reserved name")

// ErrSubdomainExhausted is returned when the collision suffixer can't
// find a free slot in maxSubdomainSuffix attempts. Triggers a 409 from
// the handler so the admin can rename and re-enroll.
var ErrSubdomainExhausted = errors.New("subdomain: collision suffix exhausted")

// maxSubdomainSuffix caps the linear collision search at -2 ... -99.
// Beyond that we refuse rather than walk into pathological loops; the
// admin should pick a less popular preferred_name.
const maxSubdomainSuffix = 99

// validateSubdomain normalises (lowercase, trim) and checks the cam's
// preferred name against the label rule and the reserved list. Returns
// the normalised name on success.
func validateSubdomain(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if !subdomainLabel.MatchString(n) {
		return "", ErrSubdomainInvalid
	}
	if cloudflare.IsReserved(n) {
		return "", ErrSubdomainReserved
	}
	return n, nil
}

// resolveSubdomain finds the first free subdomain starting from `base`,
// walking base, base-2, base-3, … up to maxSubdomainSuffix. The lookup
// uses Devices.BySubdomain; ErrNotFound means free.
//
// Returns the assigned subdomain or ErrSubdomainExhausted.
//
// A note on the race: two simultaneous registrations of the same
// preferred_name will both see "free" here and the second's INSERT
// will fail on devices_subdomain_key. The handler re-runs this
// suffixer once on that unique-violation as a defense-in-depth — the
// retry is bounded and the probability is tiny.
func resolveSubdomain(ctx context.Context, devices DeviceWriter, base string) (string, error) {
	// Try the bare name first.
	if free, err := isSubdomainFree(ctx, devices, base); err != nil {
		return "", err
	} else if free {
		return base, nil
	}
	for n := 2; n <= maxSubdomainSuffix; n++ {
		candidate := fmt.Sprintf("%s-%d", base, n)
		free, err := isSubdomainFree(ctx, devices, candidate)
		if err != nil {
			return "", err
		}
		if free {
			return candidate, nil
		}
	}
	return "", ErrSubdomainExhausted
}

func isSubdomainFree(ctx context.Context, devices DeviceWriter, sub string) (bool, error) {
	_, err := devices.BySubdomain(ctx, sub)
	if errors.Is(err, db.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// fqdn joins a subdomain with the parent zone (e.g.
// "livingroom" + "raumdock.org" → "livingroom.raumdock.org"). Both
// inputs are expected pre-normalised (lowercase, trimmed).
func fqdn(subdomain, parent string) string {
	return subdomain + "." + parent
}
