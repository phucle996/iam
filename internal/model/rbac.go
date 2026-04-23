package model

import (
	"controlplane/internal/domain/entity"
	"time"
)

// Role mirrors roles.
type Role struct {
	ID          string    `db:"id"`
	Name        string    `db:"name"`
	Level       int       `db:"level"`
	Description *string   `db:"description"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

func RoleEntityToModel(v *entity.Role) *Role {
	if v == nil {
		return nil
	}
	desc := v.Description
	return &Role{
		ID:          v.ID,
		Name:        v.Name,
		Level:       v.Level,
		Description: &desc,
		CreatedAt:   v.CreatedAt,
		UpdatedAt:   v.UpdatedAt,
	}
}

func RoleModelToEntity(v *Role) *entity.Role {
	if v == nil {
		return nil
	}
	desc := ""
	if v.Description != nil {
		desc = *v.Description
	}
	return &entity.Role{
		ID:          v.ID,
		Name:        v.Name,
		Level:       v.Level,
		Description: desc,
		CreatedAt:   v.CreatedAt,
		UpdatedAt:   v.UpdatedAt,
	}
}

// Permission mirrors permissions.
type Permission struct {
	ID          string    `db:"id"`
	Name        string    `db:"name"`
	Description *string   `db:"description"`
	CreatedAt   time.Time `db:"created_at"`
}

func PermissionEntityToModel(v *entity.Permission) *Permission {
	if v == nil {
		return nil
	}
	desc := v.Description
	return &Permission{
		ID:          v.ID,
		Name:        v.Name,
		Description: &desc,
		CreatedAt:   v.CreatedAt,
	}
}

func PermissionModelToEntity(v *Permission) *entity.Permission {
	if v == nil {
		return nil
	}

	return &entity.Permission{
		ID:          v.ID,
		Name:        v.Name,
		Description: *v.Description,
		CreatedAt:   v.CreatedAt,
	}
}

// RolePermission mirrors role_permissions.
type RolePermission struct {
	RoleID       string `db:"role_id"`
	PermissionID string `db:"permission_id"`
}

// UserRole mirrors user_roles.
type UserRole struct {
	UserID string `db:"user_id"`
	RoleID string `db:"role_id"`
}
