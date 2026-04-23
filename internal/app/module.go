package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"controlplane/infra/redis"
	"controlplane/internal/config"
	"controlplane/internal/repository"
	"controlplane/internal/service"
	"controlplane/internal/transport/http/handler"
	"controlplane/internal/transport/http/middleware"

	"controlplane/internal/ratelimit"
	"controlplane/internal/security"

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

	// Services
	DeviceService        *service.DeviceService
	TokenService         *service.TokenService
	MfaService           *service.MfaService
	AuthService          *service.AuthService
	RbacService          *service.RbacService
	AdminAPITokenService *service.AdminAPITokenService

	// Handlers
	HealthHandler *handler.HealthHandler
	AuthHandler   *handler.AuthHandler
	DeviceHandler *handler.DeviceHandler
	TokenHandler  *handler.TokenHandler
	MfaHandler    *handler.MfaHandler
	RbacHandler   *handler.RbacHandler

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
	SecretRepo := repository.NewSecretRepository(db, cfg.Security.MasterKey)

	// ── Services ──────────────────────────────────────────────────────────────
	DeviceService := service.NewDeviceService(DeviceRepo)
	TokenService := service.NewTokenService(TokenRepo, DeviceRepo, UserRepo, rdb, cfg, SecretRepo)
	MfaService := service.NewMfaService(MfaRepo, UserRepo, rdb, cfg)
	RbacService := service.NewRbacService(RbacRepo, registry, service.NewRedisRbacCacheBus(rdb))
	AdminAPITokenService := service.NewAdminAPITokenService(AdminAPITokenRepo, SecretRepo, cfg)

	AuthService := service.NewAuthService(UserRepo, DeviceService,
		TokenService, MfaService, AdminAPITokenService, rdb, cfg, SecretRepo)

	// ── Handlers ──────────────────────────────────────────────────────────────
	HealthHandler := handler.NewHealthHandler(db, rdb)
	AuthHandler := handler.NewAuthHandler(AuthService)
	DeviceHandler := handler.NewDeviceHandler(DeviceService)
	TokenHandler := handler.NewTokenHandler(TokenService)
	MfaHandler := handler.NewMfaHandler(MfaService, TokenService)
	RbacHandler := handler.NewRbacHandler(RbacService)

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

		DeviceService:        DeviceService,
		TokenService:         TokenService,
		MfaService:           MfaService,
		AuthService:          AuthService,
		RbacService:          RbacService,
		AdminAPITokenService: AdminAPITokenService,

		HealthHandler: HealthHandler,
		AuthHandler:   AuthHandler,
		DeviceHandler: DeviceHandler,
		TokenHandler:  TokenHandler,
		MfaHandler:    MfaHandler,
		RbacHandler:   RbacHandler,
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────
	if err := m.ensureInitialSecrets(context.Background()); err != nil {
		return nil, fmt.Errorf("iam module: ensure initial secrets: %w", err)
	}

	if err := m.ensureAdminBootstrapToken(context.Background()); err != nil {
		return nil, fmt.Errorf("iam module: ensure admin bootstrap token: %w", err)
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

func (m *Module) ensureInitialSecrets(ctx context.Context) error {
	repo, ok := m.Secrets.(*repository.SecretRepository)
	if !ok {
		return nil
	}

	for _, family := range security.SecretFamilies() {
		exists, err := repo.HasAny(ctx, family)
		if err != nil {
			return err
		}
		if exists {
			continue
		}

		// Generate initial secret using MasterKey as seed
		plain, err := security.GenerateToken(32, m.Cfg.Security.MasterKey)
		if err != nil {
			return err
		}

		cipher, err := security.EncryptSecret(plain, m.Cfg.Security.MasterKey)
		if err != nil {
			return err
		}

		err = repo.CreateSecretVersion(ctx, security.SecretVersion{
			Family:    family,
			Version:   1,
			Value:     cipher,
			ExpiresAt: time.Now().AddDate(10, 0, 0), // 10 years
			RotatedAt: time.Now(),
		})
		if err != nil {
			return err
		}
		slog.Info("iam: seeded initial secret", "family", family)
	}
	return nil
}

func (m *Module) ensureAdminBootstrapToken(ctx context.Context) error {
	if m == nil || m.AdminAPITokenService == nil {
		return nil
	}

	token, created, err := m.AdminAPITokenService.EnsureBootstrapToken(ctx)
	if err != nil {
		return err
	}
	if !created {
		return nil
	}

	path := strings.TrimSpace(m.Cfg.Security.AdminBootstrapTokenPath)
	if path == "" {
		return fmt.Errorf("iam module: bootstrap token path is empty")
	}

	if err := writeAdminBootstrapTokenFile(path, token); err != nil {
		return err
	}
	slog.Info("iam: bootstrap admin api token created", "path", path)
	m.scheduleBootstrapTokenFileCleanup(path)

	return nil
}

func writeAdminBootstrapTokenFile(path string, token string) error {
	if path == "" {
		return fmt.Errorf("iam module: admin bootstrap token path is empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(token+"\n"), 0o600)
}

func (m *Module) scheduleBootstrapTokenFileCleanup(path string) {
	if m == nil {
		return
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}

	ttl := m.Cfg.Security.AdminBootstrapTokenFileTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	go func() {
		timer := time.NewTimer(ttl)
		defer timer.Stop()
		<-timer.C
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Warn("iam: failed to remove bootstrap token file", "path", path, "err", err)
			return
		}
		slog.Info("iam: bootstrap token file removed", "path", path)
	}()
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

				adminDeleted, err := m.AdminAPITokenService.PurgeExpired(ctx, 500)
				if err != nil {
					slog.Warn("iam: admin api token cleanup failed", "err", err)
					continue
				}
				if adminDeleted > 0 {
					slog.Info("iam: expired admin api tokens cleaned", "deleted", adminDeleted)
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
