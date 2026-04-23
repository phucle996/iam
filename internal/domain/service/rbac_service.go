package domainsvc

import (
	"context"
	"controlplane/internal/domain/entity"
	"controlplane/internal/transport/http/middleware"
)

// RbacService handles all RBAC operations with cache-aside.
//
// ── Cache-aside ───────────────────────────────────────────────────────────────
//
//	GetRoleEntry(role):
//	  1. Check RoleRegistry (TTL 15 min)   → hit: return
//	  2. Cache miss → Postgres             → cache → return
//
// ── Invalidation on mutation ──────────────────────────────────────────────────
//
//	Every Create/Update/Delete/Assign/Revoke must call InvalidateRole
//	so the next request refetches fresh data from Postgres.
type RbacService interface {
	// LoadRole fetches role metadata from DB, used by middleware.GetRoleEntry on cache miss.
	LoadRole(ctx context.Context, role string) (middleware.RoleEntry, error)

	// InvalidateRole evicts a single role from the in-memory cache.
	InvalidateRole(ctx context.Context, role string)

	// InvalidateAll clears the entire cache.
	InvalidateAll(ctx context.Context)

	// WarmUp loads all roles from DB into cache at startup.
	WarmUp(ctx context.Context) error

	// ── Role admin ────────────────────────────────────────────────────────────
	ListRoles(ctx context.Context) ([]*entity.Role, error)
	GetRole(ctx context.Context, id string) (*entity.RoleWithPermissions, error)
	CreateRole(ctx context.Context, role *entity.Role) error
	UpdateRole(ctx context.Context, role *entity.Role) error
	DeleteRole(ctx context.Context, id string) error

	// ── Permission admin ──────────────────────────────────────────────────────
	ListPermissions(ctx context.Context) ([]*entity.Permission, error)
	CreatePermission(ctx context.Context, perm *entity.Permission) error
	AssignPermission(ctx context.Context, roleID, permID string) error
	RevokePermission(ctx context.Context, roleID, permID string) error
}
