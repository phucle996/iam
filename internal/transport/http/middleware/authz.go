package middleware

import (
	"context"
	"iam/pkg/apires"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	roleRegistry *RoleRegistry
	roleLoader   func(ctx context.Context, role string) (RoleEntry, error)
)

// InitAuthz initializes the global state used by the authorization middleware.
func InitAuthz(registry *RoleRegistry, loader func(ctx context.Context, role string) (RoleEntry, error)) {
	roleRegistry = registry
	roleLoader = loader
}

// GetRoleEntry resolves role name → RoleEntry.
// It performs cache-aside: check in-memory, miss → load DB → re-cache.
func GetRoleEntry(ctx context.Context, role string) (RoleEntry, error) {
	// 1. In-memory hit.
	if roleRegistry != nil {
		if entry, ok := roleRegistry.Get(role); ok {
			return entry, nil
		}
	}

	// 2. Miss — load from external source (usually DB).
	if roleLoader == nil {
		return RoleEntry{}, fmt.Errorf("authz: role loader not initialized")
	}

	loadCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	entry, err := roleLoader(loadCtx, role)
	if err != nil {
		return RoleEntry{}, err
	}
	entry = normalizeRoleEntry(entry)

	// 3. Cache result.
	if roleRegistry != nil {
		roleRegistry.Set(role, entry)
	}

	return entry, nil
}

// RequireLevel returns a middleware that compares the authenticated user's
// security level (from the JWT claim, injected by Access middleware) against
// the required minimum.
//
// Level semantics (same as User.SecurityLevel):
//
//	0   = highest privilege  (super-admin)
//	N   = lower privilege the higher the number  (e.g. user = 100)
//
// IMPORTANT: RequireLevel only reads from gin context — it does NOT call
// RbacService or the database. It must come before RequirePermission in the
// middleware chain so that low-level users cannot reach higher-privilege
// permission checks.
//
// Usage:
//
//	router.DELETE("/admin/users/:id",
//	    middleware.Access(),                // inject level from JWT
//	    middleware.RequireLevel(10),        // gate on raw level
//	    middleware.RequirePermission("iam:users:delete"), // perm check
//	    handler)
func RequireLevel(minLevel int) gin.HandlerFunc {
	return func(c *gin.Context) {
		level, exists := c.Get(CtxKeyLevel)
		if !exists {
			// Access middleware did not run — misconfigured route.
			apires.RespondForbidden(c, "missing level claim")
			c.Abort()
			return
		}

		userLevel, ok := level.(int)
		if !ok {
			apires.RespondForbidden(c, "invalid level claim")
			c.Abort()
			return
		}

		if userLevel > minLevel {
			apires.RespondForbidden(c, "insufficient privilege level")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequirePermission returns a middleware that verifies the authenticated user's
// role has the given permission string via GetRoleEntry (cache-aside).
//
// On cache-miss it falls back to the configured role loader (usually DB)
// and re-caches — the request is NOT rejected due to a cold cache.
//
// Usage:
//
//	middleware.RequirePermission("iam:users:delete")
func RequirePermission(perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString(CtxKeyRole)
		if role == "" {
			apires.RespondForbidden(c, "missing role claim")
			c.Abort()
			return
		}

		entry, err := GetRoleEntry(c.Request.Context(), role)
		if err != nil {
			apires.RespondForbidden(c, "role resolution failed")
			c.Abort()
			return
		}

		if !hasPermission(entry, perm) {
			apires.RespondForbidden(c, "insufficient permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func hasPermission(entry RoleEntry, perm string) bool {
	if len(entry.permissionLookup) != 0 {
		if _, ok := entry.permissionLookup["*"]; ok {
			return true
		}
		_, ok := entry.permissionLookup[perm]
		return ok
	}

	for _, permission := range entry.Permissions {
		if permission == perm || permission == "*" {
			return true
		}
	}
	return false
}
