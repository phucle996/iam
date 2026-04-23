package reqdto

// ── RBAC — Roles ──────────────────────────────────────────────────────────────

// CreateRoleRequest creates a new role.
type CreateRoleRequest struct {
	Name        string `json:"name" binding:"required"`
	Level       int    `json:"level" binding:"min=0"`
	Description string `json:"description"`
}

// UpdateRoleRequest patches a role's name, level, and description.
type UpdateRoleRequest struct {
	Name        string `json:"name" binding:"required"`
	Level       int    `json:"level" binding:"min=0"`
	Description string `json:"description"`
}

// ── RBAC — Permissions ────────────────────────────────────────────────────────

// CreatePermissionRequest creates a new permission.
type CreatePermissionRequest struct {
	Name        string `json:"name" binding:"required"` // e.g. "iam:users:delete"
	Description string `json:"description"`
}

// AssignPermissionRequest assigns an existing permission to a role.
type AssignPermissionRequest struct {
	PermissionID string `json:"permission_id" binding:"required"`
}
