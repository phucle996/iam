package app

import (
	"context"
	"iam/infra/psql"
	"iam/infra/redis"
	"iam/internal/app/bootstrap"
	"iam/internal/config"
	"iam/internal/observability"
	"iam/internal/transport/http/handler"
	"iam/internal/transport/http/middleware"
	"iam/pkg/logger"

	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type App struct {
	ctx        context.Context
	cancel     context.CancelFunc
	cfg        *config.Config
	health     *handler.HealthHandler
	module     *Module
	otel       *observability.OTel
	prom       *observability.Prometheus
	httpServer *http.Server
	// grpc       *bootstrap.GRPC
	psql *pgxpool.Pool
	rds  *redis.Client
}

func NewApplication(cfg *config.Config) (*App, error) {
	// Create context
	ctx, cancel := context.WithCancel(context.Background())

	// Init infra
	// 1. PostgreSQL
	db, err := psql.NewPostgres(ctx, &cfg.Psql)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("bootstrap: psql init failed: %w", err)
	}

	// 2. Redis (cache + stream)
	rds, err := redis.NewRedis(ctx, &cfg.Redis)
	if err != nil {
		db.Close()
		cancel()
		return nil, fmt.Errorf("bootstrap: redis init failed: %w", err)
	}

	// Run migrations
	if err := bootstrap.RunMigrations(ctx, db, cfg.Psql.Schema); err != nil {
		cancel()
		return nil, err
	}

	// Init HealthHandler
	health := handler.NewHealthHandler(db, rds.Unwrap())

	// Init gRPC (server + client manager)
	// g, err := bootstrap.InitGRPC(ctx, cfg)
	// if err != nil {
	// 	cancel()
	// 	return nil, err
	// }

	// Init Gin engine and register routes
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	if err := engine.SetTrustedProxies(cfg.App.TrustedProxies); err != nil {
		cancel()
		return nil, fmt.Errorf("bootstrap: set trusted proxies failed: %w", err)
	}

	otelObs, err := observability.InitOTel(ctx, "aurora-iam")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("bootstrap: otel init failed: %w", err)
	}

	promObs, err := observability.InitPrometheus("aurora_iam")
	if err != nil {
		_ = otelObs.Shutdown(context.Background())
		cancel()
		return nil, fmt.Errorf("bootstrap: prometheus init failed: %w", err)
	}

	engine.Use(
		gin.Recovery(),
		middleware.OTelTraceContext(otelObs),
		middleware.PrometheusHTTPMetrics(promObs),
		middleware.CORS(cfg.App.AllowedOrigins),
		middleware.CookieOriginGuard(cfg.App.AllowedOrigins),
		middleware.AccessLog(),
		middleware.RequestID(),
	)
	engine.GET("/metrics", middleware.PrometheusMetricsEndpoint(promObs))

	// Build modules
	m, err := NewModule(cfg, db, rds)
	if err != nil {
		cancel()
		return nil, err
	}

	RegisterRoutes(engine, cfg, m)

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.App.HTTPPort),
		Handler:           engine,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return &App{
		ctx:        ctx,
		cancel:     cancel,
		cfg:        cfg,
		health:     health,
		module:     m,
		otel:       otelObs,
		prom:       promObs,
		httpServer: httpSrv,
		// grpc:       g,
		psql: db,
		rds:  rds,
	}, nil
}

func (a *App) Start(cfg *config.Config) error {
	// Start gRPC server
	// go func() {
	// 	if err := a.grpc.Start(); err != nil {
	// 		logger.SysError("app", fmt.Sprintf("gRPC server stopped: %v", err))
	// 	}
	// }()

	// Start HTTP server
	go func() {
		if err := a.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.SysError("app", fmt.Sprintf("HTTP server stopped: %v", err))
		}
	}()

	// Mark application as ready to serve traffic
	a.health.MarkReady()
	logger.SysInfo("app", "Application is ready to receive traffic")

	return nil
}

func (a *App) Stop() {
	// 1. Mark as not ready to drain incoming traffic from load balancers
	a.health.MarkNotReady()

	// Optional: add a small sleep here if deployed behind a cloud load balancer (e.g. AWS ALB)
	// to allow time for the unregistered target state to propagate.

	// Stop HTTP server with bounded timeout.
	httpShutdownCtx, httpShutdownCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer httpShutdownCancel()
	if err := a.httpServer.Shutdown(httpShutdownCtx); err != nil {
		logger.SysError("app", fmt.Sprintf("HTTP server shutdown error: %v", err))
	}

	// Stop gRPC (server + close all client connections)
	// a.grpc.Stop()

	if a.module != nil {
		a.module.Stop()
	}

	if a.otel != nil {
		otelShutdownCtx, otelShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := a.otel.Shutdown(otelShutdownCtx); err != nil {
			logger.SysError("app", fmt.Sprintf("OTel shutdown error: %v", err))
		}
		otelShutdownCancel()
	}
	observability.ClearCurrentPrometheus()

	// Cancel root context
	a.cancel()

	// Close infra connections
	a.psql.Close()
	a.rds.Close()
}
