package entity

import "time"

// Role represents a system role (e.g. "admin", "operator").
type Role struct {
	ID          string
	Name        string // unique slug used in JWT "role" claim
	Level       int    // 0 = highest privilege, higher = lower
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Permission represents a single capability string (e.g. "iam:users:delete").
type Permission struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
}

// RoleWithPermissions bundles a role and its assignment permission names.
type RoleWithPermissions struct {
	Role        *Role
	Permissions []string // permission name strings, not IDs
}
