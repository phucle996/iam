package redis

import (
	"context"
	"controlplane/internal/config"
	"controlplane/internal/observability"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Client wraps a go-redis client for both cache and stream usage.
type Client struct {
	rdb *goredis.Client
}

// NewRedis creates a ready-to-use Redis client.
// Flow: build options → create client → ping → return
func NewRedis(ctx context.Context, cfg *config.RedisCfg) (*Client, error) {
	opts := &goredis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
	}

	// TLS / mTLS support
	if cfg.TLSEnabled {
		tlsCfg, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("redis: failed to build TLS config: %w", err)
		}
		opts.TLSConfig = tlsCfg
	}

	var rdb *goredis.Client
	var lastErr error

	for attempt := 1; attempt <= cfg.MaxRetries; attempt++ {
		rdb = goredis.NewClient(opts)
		rdb.AddHook(observability.NewRedisHook())

		pingCtx, pingCancel := context.WithTimeout(ctx, cfg.PingTimeout)
		lastErr = rdb.Ping(pingCtx).Err()
		pingCancel()

		if lastErr == nil {
			return &Client{rdb: rdb}, nil
		}

		_ = rdb.Close()

		if attempt < cfg.MaxRetries {
			time.Sleep(cfg.RetryInterval)
		}
	}

	return nil, fmt.Errorf("redis: failed to connect after %d attempts: %w", cfg.MaxRetries, lastErr)
}

// Close closes the Redis connection.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Unwrap returns the underlying go-redis client for cache operations.
func (c *Client) Unwrap() *goredis.Client {
	return c.rdb
}

// buildTLSConfig constructs TLS config from typed config.
func buildTLSConfig(cfg *config.RedisCfg) (*tls.Config, error) {
	tlsCfg := &tls.Config{}

	host := cfg.Addr
	if parsedHost, _, err := net.SplitHostPort(cfg.Addr); err == nil {
		host = parsedHost
	}
	tlsCfg.ServerName = strings.TrimSpace(host)

	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("redis: failed to read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		tlsCfg.RootCAs = pool
	}

	if cfg.CertPath != "" && cfg.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("redis: failed to load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
