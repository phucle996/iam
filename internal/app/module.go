package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"iam/infra/redis"
	"iam/infra/telegram"
	"iam/internal/app/bootstrap"
	"iam/internal/config"
	"iam/internal/repository"
	"iam/internal/service"
	"iam/internal/transport/http/handler"
	"iam/internal/transport/http/middleware"

	"iam/internal/ratelimit"
	"iam/internal/security"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
)

// Module encapsulates all IAM dependencies.
type Module struct {
	Cfg         *config.Config
	RateLimiter *ratelimit.Bucket
	Registry    *middleware.RoleRegistry
	Secrets     security.SecretProvider
	Rdb         *goredis.Client // raw redis client for middleware

	// Repos
	UserRepo          *repository.UserRepository
	DeviceRepo        *repository.DeviceRepository
	TokenRepo         *repository.TokenRepository
	MfaRepo           *repository.MfaRepository
	RbacRepo          *repository.RbacRepository
	AdminAPITokenRepo *repository.AdminAPITokenRepository
	AdminAuthRepo     *repository.AdminAuthRepository
	OAuthRepo         *repository.OAuthRepository

	// Services
	DeviceService        *service.DeviceService
	TokenService         *service.TokenService
	MfaService           *service.MfaService
	AuthService          *service.AuthService
	RbacService          *service.RbacService
	AdminAPITokenService *service.AdminAPITokenService
	AdminAuthService     *service.AdminAuthService
	OAuthService         *service.OAuthService

	// Handlers
	HealthHandler *handler.HealthHandler
	AuthHandler   *handler.AuthHandler
	DeviceHandler *handler.DeviceHandler
	TokenHandler  *handler.TokenHandler
	MfaHandler    *handler.MfaHandler
	RbacHandler   *handler.RbacHandler
	OAuthHandler  *handler.OAuthHandler

	stopCleanup context.CancelFunc
	cleanupDone chan struct{}
	stopRotate  context.CancelFunc
	rotateDone  chan struct{}
	rbacSync    *service.RbacCacheSync
	stopOnce    sync.Once
}

// NewModule wires all IAM dependencies and starts background jobs.
func NewModule(
	cfg *config.Config,
	db *pgxpool.Pool,
	rds *redis.Client,
) (*Module, error) {
	registry := middleware.NewRoleRegistry()

	if cfg == nil || rds == nil {
		return nil, fmt.Errorf("iam module: invalid arguments")
	}

	rdb := rds.Unwrap()
	rateLimiter := ratelimit.NewBucket(rdb)

	// ── Repositories ──────────────────────────────────────────────────────────
	UserRepo := repository.NewUserRepository(db)
	DeviceRepo := repository.NewDeviceRepository(db)
	TokenRepo := repository.NewTokenRepository(db)
	MfaRepo := repository.NewMfaRepository(db)
	RbacRepo := repository.NewRbacRepository(db)
	AdminAPITokenRepo := repository.NewAdminAPITokenRepository(db)
	AdminAuthRepo := repository.NewAdminAuthRepository(db)
	OAuthRepo := repository.NewOAuthRepository(db)
	SecretRepo := repository.NewSecretRepository(db, cfg.Security.MasterKey)

	// ── Services ──────────────────────────────────────────────────────────────
	DeviceService := service.NewDeviceService(DeviceRepo)
	TokenService := service.NewTokenService(TokenRepo, DeviceRepo, UserRepo, rdb, cfg, SecretRepo)
	MfaService := service.NewMfaService(MfaRepo, UserRepo, rdb, cfg)
	RbacService := service.NewRbacService(
		RbacRepo,
		registry,
		service.NewRedisRbacCacheBus(rdb),
		service.NewRedisRbacPermissionCache(rdb),
	)
	AdminAPITokenService := service.NewAdminAPITokenService(AdminAPITokenRepo, SecretRepo)
	AdminAuthService := service.NewAdminAuthService(AdminAuthRepo, SecretRepo, cfg)
	OAuthService := service.NewOAuthService(OAuthRepo, SecretRepo, cfg, rdb)

	AuthService := service.NewAuthService(UserRepo, DeviceService,
		TokenService, MfaService, AdminAPITokenService, rdb, cfg, SecretRepo)

	// ── Handlers ──────────────────────────────────────────────────────────────
	HealthHandler := handler.NewHealthHandler(db, rdb)
	AuthHandler := handler.NewAuthHandlerWithAdmin(AuthService, AdminAuthService)
	DeviceHandler := handler.NewDeviceHandler(DeviceService)
	TokenHandler := handler.NewTokenHandler(TokenService)
	MfaHandler := handler.NewMfaHandler(MfaService, TokenService)
	RbacHandler := handler.NewRbacHandler(RbacService)
	OAuthHandler := handler.NewOAuthHandler(OAuthService)

	m := &Module{
		Cfg:         cfg,
		RateLimiter: rateLimiter,
		Registry:    registry,
		Secrets:     SecretRepo,
		Rdb:         rdb,

		UserRepo:          UserRepo,
		DeviceRepo:        DeviceRepo,
		TokenRepo:         TokenRepo,
		MfaRepo:           MfaRepo,
		RbacRepo:          RbacRepo,
		AdminAPITokenRepo: AdminAPITokenRepo,
		AdminAuthRepo:     AdminAuthRepo,
		OAuthRepo:         OAuthRepo,

		DeviceService:        DeviceService,
		TokenService:         TokenService,
		MfaService:           MfaService,
		AuthService:          AuthService,
		RbacService:          RbacService,
		AdminAPITokenService: AdminAPITokenService,
		AdminAuthService:     AdminAuthService,
		OAuthService:         OAuthService,

		HealthHandler: HealthHandler,
		AuthHandler:   AuthHandler,
		DeviceHandler: DeviceHandler,
		TokenHandler:  TokenHandler,
		MfaHandler:    MfaHandler,
		RbacHandler:   RbacHandler,
		OAuthHandler:  OAuthHandler,
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────
	tele := telegram.NewTelegramClient(cfg.Telegram.BotToken, cfg.Telegram.ChatID)

	if err := bootstrap.EnsureInitialSecrets(context.Background(), SecretRepo, cfg.Security.MasterKey); err != nil {
		return nil, fmt.Errorf("iam module: ensure initial secrets: %w", err)
	}

	if err := bootstrap.EnsureAdminBootstrapToken(context.Background(), AdminAPITokenService, tele); err != nil {
		return nil, fmt.Errorf("iam module: ensure admin bootstrap credential: %w", err)
	}

	if err := bootstrap.EnsureAdminAuthBootstrap(context.Background(), AdminAuthService, tele); err != nil {
		return nil, fmt.Errorf("iam module: ensure admin auth bootstrap: %w", err)
	}

	// ── RBAC warm-up (best-effort, non-blocking) ──────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := RbacService.WarmUp(ctx); err != nil {
		slog.Warn("iam: rbac warm-up failed", "err", err)
	}

	m.rbacSync = service.NewRbacCacheSync(rdb, registry)
	m.rbacSync.Start(context.Background())

	m.startCleanupWorker(context.Background(), registry)
	m.startSecretRotationWorker(context.Background())

	return m, nil
}

func (m *Module) startCleanupWorker(parent context.Context, registry *middleware.RoleRegistry) {
	if m == nil || m.TokenService == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithCancel(parent)
	m.stopCleanup = cancel
	m.cleanupDone = make(chan struct{})

	go func() {
		defer close(m.cleanupDone)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if registry != nil {
					registry.EvictExpired()
				}
				deleted, err := m.TokenService.CleanupExpired(ctx)
				if err != nil {
					slog.Warn("iam: token cleanup failed", "err", err)
					continue
				}
				if deleted > 0 {
					slog.Info("iam: token cleanup completed", "deleted", deleted)
				}

			}
		}
	}()
}

func (m *Module) startSecretRotationWorker(parent context.Context) {
	if m == nil {
		return
	}
	repo, ok := m.Secrets.(*repository.SecretRepository)
	if !ok || repo == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}

	interval := m.Cfg.Security.SecretRotateInterval
	if interval <= 0 {
		return
	}
	overlap := m.Cfg.Security.SecretPreviousOverlap
	if overlap <= 0 {
		overlap = 24 * time.Hour
	}

	ctx, cancel := context.WithCancel(parent)
	m.stopRotate = cancel
	m.rotateDone = make(chan struct{})

	go func() {
		defer close(m.rotateDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, family := range security.SecretFamilies() {
					newVersion, err := repo.RotateFamily(ctx, family, overlap)
					if err != nil {
						slog.Warn("iam: secret rotation failed", "family", family, "err", err)
						continue
					}
					if newVersion > 0 {
						slog.Info("iam: secret rotated", "family", family, "version", newVersion)
					}
				}
			}
		}
	}()
}

// Stop shuts down module-level workers and is safe to call more than once.
func (m *Module) Stop() {
	if m == nil {
		return
	}

	m.stopOnce.Do(func() {
		if m.stopCleanup != nil {
			m.stopCleanup()
			if m.cleanupDone != nil {
				<-m.cleanupDone
			}
		}
		if m.stopRotate != nil {
			m.stopRotate()
			if m.rotateDone != nil {
				<-m.rotateDone
			}
		}
		if m.rbacSync != nil {
			m.rbacSync.Stop()
		}
	})
}
