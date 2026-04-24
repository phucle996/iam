package handler

import (
	"context"
	"iam/pkg/apires"
	response "iam/pkg/apires"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// HealthHandler exposes startup/readiness/liveness endpoints.
type HealthHandler struct {
	db    *pgxpool.Pool
	redis *redis.Client

	// internal state
	started atomic.Bool
	ready   atomic.Bool
}

// NewHealthHandler constructs health handler with optional deps.
func NewHealthHandler(
	db *pgxpool.Pool,
	redis *redis.Client,
) *HealthHandler {
	return &HealthHandler{
		db:    db,
		redis: redis,
	}
}

// MarkNotReady allows temporarily draining traffic.
func (h *HealthHandler) MarkNotReady() {
	h.ready.Store(false)
}

// MarkReady re-enables readiness.
func (h *HealthHandler) MarkReady() {
	h.ready.Store(true)
}

// Liveness: process health ONLY.
func (h *HealthHandler) Liveness(c *gin.Context) {
	apires.RespondSuccess(c, gin.H{
		"status": "ok",
	}, "alive")
}

// Startup: app bootstrapped or not.
func (h *HealthHandler) Startup(c *gin.Context) {
	if !h.ready.Load() {
		apires.RespondServiceUnavailable(c, "app still starting")
		return
	}
	apires.RespondSuccess(c, gin.H{"status": "ok"}, "started")
}

// Readiness: can we accept new requests?
func (h *HealthHandler) Readiness(c *gin.Context) {
	if !h.ready.Load() {
		response.RespondServiceUnavailable(c, "app not ready")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	status := gin.H{
		"postgres": "skipped",
		"redis":    "skipped",
	}

	var errs []string

	// Core dependency: Postgres
	if h.db != nil {
		if err := h.db.Ping(ctx); err != nil {
			status["postgres"] = "unhealthy"
			errs = append(errs, "postgres: "+err.Error())
		} else {
			status["postgres"] = "ok"
		}
	}

	// Core dependency: Redis
	if h.redis != nil {
		if err := h.redis.Ping(ctx).Err(); err != nil {
			status["redis"] = "unhealthy"
			errs = append(errs, "redis: "+err.Error())
		} else {
			status["redis"] = "ok"
		}
	}

	// Only FAIL readiness for sync core deps
	if len(errs) > 0 {
		apires.RespondServiceUnavailable(c, "readiness failed: "+joinErrors(errs))
		return
	}

	apires.RespondSuccess(c, status, "ready")
}

func joinErrors(errs []string) string {
	switch len(errs) {
	case 0:
		return ""
	case 1:
		return errs[0]
	default:
		out := errs[0]
		for _, e := range errs[1:] {
			out += "; " + e
		}
		return out
	}
}
