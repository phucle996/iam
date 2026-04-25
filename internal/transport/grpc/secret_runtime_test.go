package grpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"iam/internal/security"
	"iam/internal/transport/grpc/secretpb"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type fakeSecretProvider struct{}

func (fakeSecretProvider) GetActive(family string) (security.SecretVersion, error) {
	items, err := fakeSecretProvider{}.GetCandidates(family)
	if err != nil {
		return security.SecretVersion{}, err
	}
	return items[0], nil
}

func (fakeSecretProvider) GetCandidates(family string) ([]security.SecretVersion, error) {
	if family != security.SecretFamilyAccess {
		return nil, security.ErrSecretUnavailable
	}
	now := time.Now().UTC()
	return []security.SecretVersion{{
		Family:    family,
		Version:   2,
		Value:     "access-secret",
		ExpiresAt: now.Add(time.Hour),
		RotatedAt: now,
	}}, nil
}

func TestSecretRuntimeServiceGetCandidatesWithMTLS(t *testing.T) {
	addr, clientTLS, stop := startSecretRuntimeTestServer(t)
	defer stop()

	conn, err := ggrpc.NewClient(
		addr,
		ggrpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := secretpb.NewSecretRuntimeServiceClient(conn)
	resp, err := client.GetSecretCandidates(ctx, &secretpb.GetSecretCandidatesRequest{Families: []string{security.SecretFamilyAccess}})
	if err != nil {
		t.Fatalf("invoke get candidates: %v", err)
	}

	items := resp.GetFamilies()[security.SecretFamilyAccess].GetCandidates()
	if len(items) != 1 || items[0].Value != "access-secret" || items[0].Version != 2 {
		t.Fatalf("unexpected candidates: %#v", resp.GetFamilies())
	}
}

func TestSecretRuntimeServiceRejectsClientWithoutCertificate(t *testing.T) {
	addr, clientTLS, stop := startSecretRuntimeTestServer(t)
	defer stop()
	clientTLS.Certificates = nil

	conn, err := ggrpc.NewClient(
		addr,
		ggrpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := secretpb.NewSecretRuntimeServiceClient(conn)
	_, err = client.GetSecretCandidates(ctx, &secretpb.GetSecretCandidatesRequest{Families: []string{security.SecretFamilyAccess}})
	if err == nil {
		t.Fatalf("expected mTLS failure without client certificate")
	}
}

func startSecretRuntimeTestServer(t *testing.T) (string, *tls.Config, func()) {
	t.Helper()

	caCert, caKey := mustCreateCA(t)
	serverCert := mustCreateSignedCert(t, caCert, caKey, true)
	clientCert := mustCreateSignedCert(t, caCert, caKey, false)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	server := ggrpc.NewServer(ggrpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	})))
	RegisterSecretRuntimeService(server, fakeSecretProvider{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		_ = server.Serve(lis)
	}()

	clientTLS := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
	return lis.Addr().String(), clientTLS, func() {
		server.Stop()
		_ = lis.Close()
	}
}

func mustCreateCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Aurora Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	return cert, key
}

func mustCreateSignedCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, server bool) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load leaf pair: %v", err)
	}
	return cert
}
