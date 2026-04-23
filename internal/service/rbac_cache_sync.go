package service

import (
	"context"
	"controlplane/internal/transport/http/middleware"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultRbacSyncInterval = 30 * time.Second

type RbacCacheSync struct {
	rdb      *redis.Client
	registry *middleware.RoleRegistry
	interval time.Duration

	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
	started atomic.Bool
	epoch   int64
}

func NewRbacCacheSync(rdb *redis.Client, registry *middleware.RoleRegistry) *RbacCacheSync {
	if rdb == nil || registry == nil {
		return nil
	}
	return &RbacCacheSync{
		rdb:      rdb,
		registry: registry,
		interval: defaultRbacSyncInterval,
		done:     make(chan struct{}),
	}
}

func (s *RbacCacheSync) Start(parent context.Context) {
	if s == nil || s.rdb == nil || s.registry == nil {
		return
	}
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel

	pubsub := s.rdb.Subscribe(ctx, rbacInvalidateChannel)
	if _, err := pubsub.Receive(ctx); err != nil {
		_ = pubsub.Close()
		s.once.Do(func() {
			if s.cancel != nil {
				s.cancel()
			}
		})
		s.started.Store(false)
		return
	}

	initialEpoch, err := s.loadEpoch(ctx)
	if err == nil {
		atomic.StoreInt64(&s.epoch, initialEpoch)
	}

	go s.loop(ctx, pubsub)
}

func (s *RbacCacheSync) Stop() {
	if s == nil {
		return
	}
	if !s.started.Load() {
		return
	}
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
	})
	<-s.done
}

func (s *RbacCacheSync) loop(ctx context.Context, pubsub *redis.PubSub) {
	defer close(s.done)
	defer func() { _ = pubsub.Close() }()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-pubsub.Channel():
			if !ok {
				return
			}
			s.handleMessage(msg.Payload)
		case <-ticker.C:
			s.syncEpoch(ctx)
		}
	}
}

func (s *RbacCacheSync) handleMessage(payload string) {
	var event rbacInvalidateEvent
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		return
	}

	current := atomic.LoadInt64(&s.epoch)
	if event.Epoch > current {
		atomic.StoreInt64(&s.epoch, event.Epoch)
	}

	switch event.Kind {
	case rbacInvalidateAll:
		s.registry.InvalidateAll()
	case rbacInvalidateRole:
		if event.Role != "" {
			s.registry.Invalidate(event.Role)
		}
	}
}

func (s *RbacCacheSync) syncEpoch(ctx context.Context) {
	currentEpoch, err := s.loadEpoch(ctx)
	if err != nil {
		return
	}

	last := atomic.LoadInt64(&s.epoch)
	if currentEpoch <= last {
		return
	}

	s.registry.InvalidateAll()
	atomic.StoreInt64(&s.epoch, currentEpoch)
}

func (s *RbacCacheSync) loadEpoch(ctx context.Context) (int64, error) {
	if s == nil || s.rdb == nil {
		return 0, nil
	}

	raw, err := s.rdb.Get(ctx, rbacEpochKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("rbac cache sync: load epoch: %w", err)
	}

	epoch, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("rbac cache sync: parse epoch: %w", err)
	}
	return epoch, nil
}
