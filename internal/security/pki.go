package security

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

const dataPlaneCommonNamePrefix = "data-plane:"

type CertificateAuthority struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
}

func LoadCertificateAuthority(certPath, keyPath string) (*CertificateAuthority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("security: read ca cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("security: read ca key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("security: decode ca cert pem")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("security: parse ca cert: %w", err)
	}

	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("security: load ca key pair: %w", err)
	}

	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("security: ca private key does not implement crypto.Signer")
	}

	return &CertificateAuthority{
		cert:    cert,
		key:     signer,
		certPEM: certPEM,
	}, nil
}

func (ca *CertificateAuthority) CertPEM() string {
	if ca == nil {
		return ""
	}
	return string(ca.certPEM)
}

func (ca *CertificateAuthority) SignDataPlaneClientCertificate(csrPEM, dataPlaneID string, ttl time.Duration) (string, string, time.Time, error) {
	if ca == nil || ca.cert == nil || ca.key == nil {
		return "", "", time.Time{}, errors.New("security: certificate authority is not initialized")
	}
	if strings.TrimSpace(dataPlaneID) == "" {
		return "", "", time.Time{}, errors.New("security: data plane id is empty")
	}
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}

	csr, err := ParseCertificateRequestPEM(csrPEM)
	if err != nil {
		return "", "", time.Time{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("security: generate certificate serial: %w", err)
	}

	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(ttl)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   DataPlaneCommonName(dataPlaneID),
			Organization: []string{"aurora-controlplane"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("security: create client certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM), serialNumber.Text(16), notAfter, nil
}

func ParseCertificateRequestPEM(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(csrPEM)))
	if block == nil {
		return nil, errors.New("security: decode certificate request pem")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("security: parse certificate request: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("security: verify certificate request: %w", err)
	}

	return csr, nil
}

func DataPlaneCommonName(dataPlaneID string) string {
	return dataPlaneCommonNamePrefix + strings.TrimSpace(dataPlaneID)
}

func DataPlaneIDFromCertificate(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("security: nil certificate")
	}

	commonName := strings.TrimSpace(cert.Subject.CommonName)
	if !strings.HasPrefix(commonName, dataPlaneCommonNamePrefix) {
		return "", errors.New("security: unexpected certificate common name")
	}

	dataPlaneID := strings.TrimPrefix(commonName, dataPlaneCommonNamePrefix)
	if strings.TrimSpace(dataPlaneID) == "" {
		return "", errors.New("security: empty data plane id in certificate")
	}

	return dataPlaneID, nil
}
