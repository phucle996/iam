package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"iam/internal/config"
	"iam/pkg/logger"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type GRPC struct {
	Server *grpc.Server
	lis    net.Listener
}

func InitGRPC(cfg *config.GRPCCfg) (*GRPC, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	tlsConfig, err := buildGRPCServerTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	port := strings.TrimSpace(cfg.ServerPort)

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return nil, fmt.Errorf("grpc: listen on port %s: %w", port, err)
	}

	return &GRPC{
		Server: grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig))),
		lis:    lis,
	}, nil
}

func (g *GRPC) Start() error {
	return g.Server.Serve(g.lis)
}

func (g *GRPC) Stop() {
	g.Server.GracefulStop()
}

func buildGRPCServerTLSConfig(cfg *config.GRPCCfg) (*tls.Config, error) {
	if strings.TrimSpace(cfg.ServerTLSCertPath) == "" || strings.TrimSpace(cfg.ServerTLSKeyPath) == "" {
		return nil, errors.New("grpc: server tls cert and key are required")
	}
	if strings.TrimSpace(cfg.ClientCACertPath) == "" {
		return nil, errors.New("grpc: client ca is required for mtls")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.ServerTLSCertPath, cfg.ServerTLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("grpc: load server cert/key: %w", err)
	}

	clientCAPEM, err := os.ReadFile(cfg.ClientCACertPath)
	if err != nil {
		return nil, fmt.Errorf("grpc: read client ca: %w", err)
	}
	clientCAPool := x509.NewCertPool()
	if ok := clientCAPool.AppendCertsFromPEM(clientCAPEM); !ok {
		return nil, errors.New("grpc: append client ca")
	}

	logger.SysInfo("grpc", "IAM internal gRPC server configured with mTLS")
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
