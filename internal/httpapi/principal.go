package httpapi

import (
	"context"

	"github.com/raumdock/rdoc-camhub/internal/db"
)

// Principal is the authenticated user attached to a request by
// RequireSession. Read it from the request context via PrincipalFrom.
type Principal struct {
	UserID    int64
	Email     string
	Role      db.Role
	SessionID string
}

type ctxKeyPrincipal struct{}

func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal{}, p)
}

// PrincipalFrom returns the principal attached by RequireSession. The bool
// is false when no middleware ran or the request is anonymous.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKeyPrincipal{}).(Principal)
	return p, ok
}
