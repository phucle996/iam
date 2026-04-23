package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	rbacInvalidateChannel = "iam:rbac:invalidate"
	rbacEpochKey          = "iam:rbac:epoch"
)

type rbacInvalidateKind string

const (
	rbacInvalidateRole rbacInvalidateKind = "role"
	rbacInvalidateAll  rbacInvalidateKind = "all"
)

type rbacInvalidateEvent struct {
	Kind        rbacInvalidateKind `json:"kind"`
	Role        string             `json:"role,omitempty"`
	Epoch       int64              `json:"epoch"`
	PublishedAt time.Time          `json:"published_at"`
}

type RbacCacheBus interface {
	PublishInvalidateRole(ctx context.Context, role string) error
	PublishInvalidateAll(ctx context.Context) error
}

type RedisRbacCacheBus struct {
	rdb *redis.Client
}

func NewRedisRbacCacheBus(rdb *redis.Client) *RedisRbacCacheBus {
	if rdb == nil {
		return nil
	}
	return &RedisRbacCacheBus{rdb: rdb}
}

func (b *RedisRbacCacheBus) PublishInvalidateRole(ctx context.Context, role string) error {
	if b == nil || b.rdb == nil {
		return nil
	}
	return b.publish(ctx, rbacInvalidateEvent{
		Kind: rbacInvalidateRole,
		Role: strings.TrimSpace(role),
	})
}

func (b *RedisRbacCacheBus) PublishInvalidateAll(ctx context.Context) error {
	if b == nil || b.rdb == nil {
		return nil
	}
	return b.publish(ctx, rbacInvalidateEvent{Kind: rbacInvalidateAll})
}

func (b *RedisRbacCacheBus) publish(ctx context.Context, event rbacInvalidateEvent) error {
	epoch, err := b.rdb.Incr(ctx, rbacEpochKey).Result()
	if err != nil {
		return fmt.Errorf("rbac cache bus: bump epoch: %w", err)
	}

	event.Epoch = epoch
	event.PublishedAt = time.Now().UTC()
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("rbac cache bus: marshal event: %w", err)
	}

	if err := b.rdb.Publish(ctx, rbacInvalidateChannel, payload).Err(); err != nil {
		return fmt.Errorf("rbac cache bus: publish invalidation: %w", err)
	}

	return nil
}
