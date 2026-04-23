package svc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"controlplane/internal/domain/entity"
	"controlplane/internal/security"
	"controlplane/internal/service"
)

func TestDeviceServiceRebindVerifiesSignatureAndRotatesKey(t *testing.T) {
	ctx := context.Background()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate replacement keypair: %v", err)
	}

	deviceRepo := &stubDeviceRepo{
		device: &entity.Device{
			ID:              "device-1",
			UserID:          "user-1",
			DevicePublicKey: encodeEd25519PublicKeyPEM(pub),
			KeyAlgorithm:    security.AlgEd25519,
		},
		challenge: &entity.DeviceChallenge{
			ChallengeID: "challenge-1",
			DeviceID:    "device-1",
			UserID:      "user-1",
			Nonce:       "nonce-abc-123",
			ExpiresAt:   time.Now().UTC().Add(time.Minute),
			CreatedAt:   time.Now().UTC(),
		},
	}
	svc := service.NewDeviceService(deviceRepo)

	proof := &entity.DeviceProof{
		ChallengeID:  "challenge-1",
		DeviceID:     "device-1",
		Signature:    signNonceWithEd25519(priv, deviceRepo.challenge.Nonce),
		NewPublicKey: encodeEd25519PublicKeyPEM(newPub),
		NewAlgorithm: security.AlgEd25519,
	}

	if err := svc.Rebind(ctx, "user-1", proof); err != nil {
		t.Fatalf("rebind device: %v", err)
	}

	if deviceRepo.challenge != nil {
		t.Fatalf("expected challenge to be consumed")
	}
	if deviceRepo.device == nil {
		t.Fatalf("expected device to remain present")
	}
	if deviceRepo.rotatedPublicKey != strings.TrimSpace(proof.NewPublicKey) {
		t.Fatalf("expected rotate call to persist the new public key")
	}
	if deviceRepo.rotatedAlgorithm != proof.NewAlgorithm {
		t.Fatalf("expected rotate call to persist the new algorithm")
	}
}

func TestDeviceServiceResolveDeviceFillsLegacyEmptyKeyRow(t *testing.T) {
	ctx := context.Background()

	pub, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa keypair: %v", err)
	}

	deviceRepo := &stubDeviceRepo{
		device: &entity.Device{
			ID:           "device-legacy",
			UserID:       "user-1",
			Fingerprint:  "install-abc",
			LastActiveAt: time.Now().UTC().Add(-time.Hour),
			CreatedAt:    time.Now().UTC().Add(-time.Hour),
		},
	}
	svc := service.NewDeviceService(deviceRepo)

	device, err := svc.ResolveDevice(ctx, "user-1", "install-abc", encodeECDSAP256PublicKeyPEM(&pub.PublicKey), "ES256")
	if err != nil {
		t.Fatalf("resolve device: %v", err)
	}

	if deviceRepo.device == nil {
		t.Fatalf("expected device to remain present")
	}
	if deviceRepo.device.DevicePublicKey == "" {
		t.Fatalf("expected legacy empty-key row to be bound")
	}
	if deviceRepo.device.KeyAlgorithm != security.AlgECDSAP256 {
		t.Fatalf("expected algorithm to normalize to %q, got %q", security.AlgECDSAP256, deviceRepo.device.KeyAlgorithm)
	}
	if device.ID != "device-legacy" {
		t.Fatalf("expected same device row to be refreshed, got %q", device.ID)
	}
}
