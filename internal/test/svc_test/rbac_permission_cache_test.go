package svc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"iam/internal/domain/entity"
	"iam/internal/service"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisRbacPermissionCacheWritesHashedRoleKey(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	cache := service.NewRedisRbacPermissionCache(client)
	err := cache.SetRole(context.Background(), &entity.RoleWithPermissions{
		Role: &entity.Role{
			Name:  "Admin",
			Level: 1,
		},
		Permissions: []string{"smtp:gateway:read", "smtp:gateway:write"},
	})
	if err != nil {
		t.Fatalf("set role permissions: %v", err)
	}

	sum := sha256.Sum256([]byte(strings.ToLower("Admin")))
	key := "iam:rbac:role_permissions:" + hex.EncodeToString(sum[:])
	raw, err := client.Get(context.Background(), key).Result()
	if err != nil {
		t.Fatalf("read role permissions: %v", err)
	}

	var payload struct {
		Role        string   `json:"role"`
		Level       int      `json:"level"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Role != "admin" {
		t.Fatalf("expected normalized role admin, got %q", payload.Role)
	}
	if payload.Level != 1 {
		t.Fatalf("expected level 1, got %d", payload.Level)
	}
	if len(payload.Permissions) != 2 || payload.Permissions[0] != "smtp:gateway:read" || payload.Permissions[1] != "smtp:gateway:write" {
		t.Fatalf("unexpected permissions: %#v", payload.Permissions)
	}
}
