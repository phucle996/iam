package svc_test

import (
	"context"
	"testing"
	"time"

	"controlplane/internal/service"
	"controlplane/internal/transport/http/middleware"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRbacCacheSyncInvalidatesRolesFromPubSub(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	registry := middleware.NewRoleRegistry()
	registry.Set("admin", middleware.RoleEntry{Level: 0})
	registry.Set("viewer", middleware.RoleEntry{Level: 10})

	syncer := service.NewRbacCacheSync(client, registry)
	if syncer == nil {
		t.Fatal("expected syncer")
	}
	syncer.Start(context.Background())
	t.Cleanup(syncer.Stop)

	bus := service.NewRedisRbacCacheBus(client)
	if err := bus.PublishInvalidateRole(context.Background(), "admin"); err != nil {
		t.Fatalf("publish role invalidation: %v", err)
	}
	waitForCacheEmptyRole(t, registry, "admin")

	registry.Set("viewer", middleware.RoleEntry{Level: 10})
	if err := bus.PublishInvalidateAll(context.Background()); err != nil {
		t.Fatalf("publish flush-all invalidation: %v", err)
	}
	waitForCacheEmptyRole(t, registry, "viewer")
}

func waitForCacheEmptyRole(t *testing.T, registry *middleware.RoleRegistry, role string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := registry.Get(role); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected role %q to be invalidated", role)
}
