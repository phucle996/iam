package bootstrap

import (
	"context"
	"controlplane/internal/config"
	"controlplane/pkg/logger"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPC holds both inbound server and outbound client manager.
type GRPC struct {
	Server  *grpc.Server
	Clients *GRPCClientManager
	lis     net.Listener
	cfg     *config.GRPCCfg
}

// GRPCClientManager manages reusable outbound gRPC connections.
// Connections are stored by service name — no per-request dial.
type GRPCClientManager struct {
	mu    sync.RWMutex
	conns map[string]*grpc.ClientConn
	cfg   *config.GRPCCfg
}

// InitGRPC initializes both gRPC server and client manager.
func InitGRPC(ctx context.Context, cfg *config.Config) (*GRPC, error) {
	// Server
	serverOptions := make([]grpc.ServerOption, 0, 1)
	if cfg.GRPC.ServerTLSEnabled {
		tlsConfig, err := buildGRPCServerTLSConfig(&cfg.GRPC)
		if err != nil {
			return nil, err
		}
		serverOptions = append(serverOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}
	server := grpc.NewServer(serverOptions...)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.GRPC.ServerPort))
	if err != nil {
		return nil, fmt.Errorf("grpc: failed to listen on port %s: %w", cfg.GRPC.ServerPort, err)
	}

	// Client manager
	clients := &GRPCClientManager{
		conns: make(map[string]*grpc.ClientConn),
		cfg:   &cfg.GRPC,
	}

	return &GRPC{
		Server:  server,
		Clients: clients,
		lis:     lis,
		cfg:     &cfg.GRPC,
	}, nil
}

// Start begins serving gRPC (blocking — run in goroutine).
func (g *GRPC) Start() error {
	return g.Server.Serve(g.lis)
}

// Stop gracefully stops the gRPC server and closes all client connections.
func (g *GRPC) Stop() {
	g.Server.GracefulStop()

	g.Clients.CloseAll()
}

// --- Client Manager ---

// Dial creates or reuses a gRPC client connection for a named service.
// Uses config-driven targets. Connection is reused on subsequent calls.
func (m *GRPCClientManager) Dial(ctx context.Context, serviceName, target string) (*grpc.ClientConn, error) {
	m.mu.RLock()
	if conn, ok := m.conns[serviceName]; ok {
		m.mu.RUnlock()
		return conn, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if conn, ok := m.conns[serviceName]; ok {
		return conn, nil
	}

	// Build credentials
	var creds credentials.TransportCredentials
	if m.cfg.ClientTLSEnabled {
		tlsConfig, err := buildGRPCClientTLSConfig(m.cfg)
		if err != nil {
			return nil, fmt.Errorf("grpc: failed to build client TLS config: %w", err)
		}
		creds = credentials.NewTLS(tlsConfig)
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc: failed to dial %s (%s): %w", serviceName, target, err)
	}

	m.conns[serviceName] = conn
	return conn, nil
}

// Get returns an existing connection by service name, or nil if not found.
func (m *GRPCClientManager) Get(serviceName string) *grpc.ClientConn {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.conns[serviceName]
}

// CloseAll closes all client connections.
func (m *GRPCClientManager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, conn := range m.conns {
		if err := conn.Close(); err != nil {
			logger.SysError("grpc_client", fmt.Sprintf("grpc: error closing client %s: %v", name, err))
		}
	}
	m.conns = make(map[string]*grpc.ClientConn)
}

// buildGRPCClientTLSConfig constructs TLS config from typed config.
func buildGRPCClientTLSConfig(cfg *config.GRPCCfg) (*tls.Config, error) {
	tlsCfg := &tls.Config{}

	if cfg.ClientCACertPath != "" {
		caCert, err := os.ReadFile(cfg.ClientCACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		tlsCfg.RootCAs = pool
	}

	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

func buildGRPCServerTLSConfig(cfg *config.GRPCCfg) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("grpc: server tls config is nil")
	}
	if cfg.ServerCertPath == "" || cfg.ServerKeyPath == "" {
		return nil, errors.New("grpc: server tls requires GRPC_SERVER_TLS_CERT and GRPC_SERVER_TLS_KEY")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("grpc: load server cert/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.DataPlaneClientCACertPath != "" {
		caCert, err := os.ReadFile(cfg.DataPlaneClientCACertPath)
		if err != nil {
			return nil, fmt.Errorf("grpc: read dataplane client ca cert: %w", err)
		}

		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caCert); !ok {
			return nil, errors.New("grpc: append dataplane client ca cert")
		}

		tlsCfg.ClientCAs = pool
	}

	return tlsCfg, nil
}
