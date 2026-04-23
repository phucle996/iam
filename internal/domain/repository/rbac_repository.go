package domainrepo

import (
	"context"

	"controlplane/internal/domain/entity"
)

// RbacRepository handles persistence for roles and permissions.
type RbacRepository interface {
	// GetRoleByName loads a role with all its assigned permission names.
	// This is the cache-miss fallback used by RbacService.
	GetRoleByName(ctx context.Context, name string) (*entity.RoleWithPermissions, error)

	ListRoleEntries(ctx context.Context) ([]*entity.RoleWithPermissions, error)

	ListRoles(ctx context.Context) ([]*entity.Role, error)
	GetRoleByID(ctx context.Context, id string) (*entity.Role, error)
	CreateRole(ctx context.Context, role *entity.Role) error
	UpdateRole(ctx context.Context, role *entity.Role) error
	DeleteRole(ctx context.Context, id string) error

	ListPermissions(ctx context.Context) ([]*entity.Permission, error)
	GetPermissionByID(ctx context.Context, id string) (*entity.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*entity.Permission, error)
	CreatePermission(ctx context.Context, perm *entity.Permission) error
	AssignPermission(ctx context.Context, roleID, permissionID string) error
	RevokePermission(ctx context.Context, roleID, permissionID string) error
}
