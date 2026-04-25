package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"iam/internal/domain/entity"

	"github.com/redis/go-redis/v9"
)

const rbacRolePermissionsKeyPrefix = "iam:rbac:role_permissions"

type rbacRolePermissionsPayload struct {
	Role        string    `json:"role"`
	Level       int       `json:"level"`
	Permissions []string  `json:"permissions"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RbacPermissionCache interface {
	SetRole(ctx context.Context, role *entity.RoleWithPermissions) error
	DeleteRole(ctx context.Context, role string) error
}

type RedisRbacPermissionCache struct {
	rdb    *redis.Client
	prefix string
}

func NewRedisRbacPermissionCache(rdb *redis.Client) *RedisRbacPermissionCache {
	if rdb == nil {
		return nil
	}
	return &RedisRbacPermissionCache{
		rdb:    rdb,
		prefix: rbacRolePermissionsKeyPrefix,
	}
}

func (c *RedisRbacPermissionCache) SetRole(ctx context.Context, role *entity.RoleWithPermissions) error {
	if c == nil || c.rdb == nil || role == nil || role.Role == nil {
		return nil
	}
	roleName := normalizeRbacRoleName(role.Role.Name)
	if roleName == "" {
		return nil
	}
	payload, err := json.Marshal(rbacRolePermissionsPayload{
		Role:        roleName,
		Level:       role.Role.Level,
		Permissions: role.Permissions,
		UpdatedAt:   time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("rbac permission cache: marshal role: %w", err)
	}
	if err := c.rdb.Set(ctx, rbacRolePermissionsKey(c.prefix, roleName), payload, 0).Err(); err != nil {
		return fmt.Errorf("rbac permission cache: set role: %w", err)
	}
	return nil
}

func (c *RedisRbacPermissionCache) DeleteRole(ctx context.Context, role string) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	role = normalizeRbacRoleName(role)
	if role == "" {
		return nil
	}
	if err := c.rdb.Del(ctx, rbacRolePermissionsKey(c.prefix, role)).Err(); err != nil {
		return fmt.Errorf("rbac permission cache: delete role: %w", err)
	}
	return nil
}

func rbacRolePermissionsKey(prefix, role string) string {
	sum := sha256.Sum256([]byte(normalizeRbacRoleName(role)))
	return strings.TrimRight(strings.TrimSpace(prefix), ":") + ":" + hex.EncodeToString(sum[:])
}

func normalizeRbacRoleName(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}
