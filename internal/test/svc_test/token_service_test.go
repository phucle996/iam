package svc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"iam/internal/config"
	"iam/internal/domain/entity"
	"iam/internal/security"
	"iam/internal/service"
	"iam/pkg/errorx"

	miniredis "github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
)

const (
	cleanupBatchSize = int64(500)
)

type casTokenRepo struct {
	mu       sync.Mutex
	consumed bool
	token    *entity.RefreshToken
}

func (r *casTokenRepo) Create(ctx context.Context, token *entity.RefreshToken) error { return nil }
func (r *casTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneRefreshToken(r.token), nil
}
func (r *casTokenRepo) Revoke(ctx context.Context, tokenID string) error { return nil }
func (r *casTokenRepo) ConsumeActive(ctx context.Context, tokenID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.consumed {
		return false, nil
	}
	r.consumed = true
	return true, nil
}
func (r *casTokenRepo) RevokeAllByDevice(ctx context.Context, deviceID string) error { return nil }
func (r *casTokenRepo) RevokeAllByUser(ctx context.Context, userID string) error     { return nil }
func (r *casTokenRepo) DeleteExpired(ctx context.Context) (int64, error)             { return 0, nil }
func (r *casTokenRepo) DeleteExpiredBatch(ctx context.Context, limit int64) (int64, error) {
	return 0, nil
}

func TestTokenServiceRevokeAllByUser(t *testing.T) {
	t.Parallel()

	repo := &stubTokenRepo{}
	svc := service.NewTokenService(repo, nil, nil, nil, nil, nil)

	if err := svc.RevokeAllByUser(context.Background(), "user-123"); err != nil {
		t.Fatalf("revoke all by user: %v", err)
	}
	if repo.revokedUserID != "user-123" {
		t.Fatalf("expected revoke target user-123, got %q", repo.revokedUserID)
	}
}

func TestTokenServiceCleanupExpiredDelegatesToRepo(t *testing.T) {
	t.Parallel()

	repo := &stubTokenRepo{deletedExpired: 7}
	svc := service.NewTokenService(repo, nil, nil, nil, nil, nil)

	deleted, err := svc.CleanupExpired(context.Background())
	if err != nil {
		t.Fatalf("cleanup expired: %v", err)
	}
	if !repo.deleteExpiredBatchCalled {
		t.Fatalf("expected cleanup to call repository delete expired batch")
	}
	if repo.deleteExpiredBatchLimit != cleanupBatchSize {
		t.Fatalf("expected cleanup batch size %d, got %d", cleanupBatchSize, repo.deleteExpiredBatchLimit)
	}
	if deleted != 7 {
		t.Fatalf("expected 7 deleted rows, got %d", deleted)
	}
}

func TestTokenServiceCleanupExpiredRunsMultipleBatches(t *testing.T) {
	t.Parallel()

	repo := &stubTokenRepo{
		deleteExpiredBatchSeq: []int64{cleanupBatchSize, 200},
	}
	svc := service.NewTokenService(repo, nil, nil, nil, nil, nil)

	deleted, err := svc.CleanupExpired(context.Background())
	if err != nil {
		t.Fatalf("cleanup expired: %v", err)
	}
	if repo.deleteExpiredBatchCalls != 2 {
		t.Fatalf("expected 2 batch calls, got %d", repo.deleteExpiredBatchCalls)
	}
	if deleted != cleanupBatchSize+200 {
		t.Fatalf("expected total deleted %d, got %d", cleanupBatchSize+200, deleted)
	}
}

func TestTokenServiceRotateRejectsUnboundDevice(t *testing.T) {
	ctx := context.Background()

	rawToken := "refresh-token-123"
	userRepo := &stubUserRepo{
		usersByID: map[string]*entity.User{
			"user-1": {
				ID:            "user-1",
				Role:          "user",
				Status:        "active",
				SecurityLevel: 4,
			},
		},
	}
	tokenRepo := &stubTokenRepo{
		consumeActiveOK: true,
		tokenByHash: &entity.RefreshToken{
			ID:        "token-1",
			DeviceID:  "device-1",
			UserID:    "user-1",
			TokenHash: "hash",
			ExpiresAt: time.Now().UTC().Add(time.Hour),
			CreatedAt: time.Now().UTC(),
		},
	}
	deviceRepo := &stubDeviceRepo{
		device: &entity.Device{
			ID:              "device-1",
			UserID:          "user-1",
			DevicePublicKey: "",
			KeyAlgorithm:    security.AlgECDSAP256,
		},
	}
	svc := service.NewTokenService(
		tokenRepo,
		deviceRepo,
		userRepo,
		nil,
		nil,
		&fakeSecretProvider{
			active: security.SecretVersion{Value: "refresh-secret"},
		},
	)

	result, err := svc.Rotate(ctx, &entity.RotateToken{
		RawRefreshToken: rawToken,
		DeviceID:        "device-1",
		JTI:             "jti-1",
		IssuedAt:        time.Now().UTC().Unix(),
		HTM:             "POST",
		HTU:             "http://localhost:8080/api/v1/auth/refresh",
		TokenHash:       security.HashRefreshToken(rawToken),
		Signature:       "signature",
	})
	if !errors.Is(err, errorx.ErrRefreshDeviceUnbound) {
		t.Fatalf("expected unbound device error, got result=%v err=%v", result, err)
	}
	if tokenRepo.revokedTokenID != "" {
		t.Fatalf("expected refresh token not to be revoked when device is unbound")
	}
}

func TestTokenServiceRotateRejectsReplayJTI(t *testing.T) {
	ctx := context.Background()

	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})

	rawToken := "refresh-token-123"
	userRepo := &stubUserRepo{
		usersByID: map[string]*entity.User{
			"user-1": {
				ID:            "user-1",
				Role:          "user",
				Status:        "active",
				SecurityLevel: 4,
			},
		},
	}
	tokenRepo := &stubTokenRepo{
		consumeActiveOK: true,
		tokenByHash: &entity.RefreshToken{
			ID:        "token-1",
			DeviceID:  "device-1",
			UserID:    "user-1",
			TokenHash: security.HashRefreshToken(rawToken),
			ExpiresAt: time.Now().UTC().Add(time.Hour),
			CreatedAt: time.Now().UTC(),
		},
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}

	deviceRepo := &stubDeviceRepo{
		device: &entity.Device{
			ID:              "device-1",
			UserID:          "user-1",
			DevicePublicKey: encodeEd25519PublicKeyPEM(pub),
			KeyAlgorithm:    security.AlgEd25519,
		},
	}
	svc := service.NewTokenService(
		tokenRepo,
		deviceRepo,
		userRepo,
		client,
		&config.Config{
			App: config.AppCfg{
				PublicURL: "https://controlplane.example.com",
			},
			Security: config.SecurityCfg{
				AccessSecretTTL: time.Minute,
				RefreshTokenTTL: time.Minute,
			},
		},
		&fakeSecretProvider{
			active: security.SecretVersion{Value: "test-refresh-secret"},
		},
	)

	req := &entity.RotateToken{
		RawRefreshToken: rawToken,
		DeviceID:        "device-1",
		JTI:             "jti-1",
		IssuedAt:        time.Now().UTC().Unix(),
		HTM:             "POST",
		HTU:             "https://controlplane.example.com/api/v1/auth/refresh",
		TokenHash:       security.HashRefreshToken(rawToken),
	}
	req.Signature = signDevicePayloadForTest(t, priv, req)

	firstResult, err := svc.Rotate(ctx, req)
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	if firstResult == nil || firstResult.AccessToken == "" {
		t.Fatalf("expected first rotation to succeed")
	}

	secondResult, err := svc.Rotate(ctx, req)
	if !errors.Is(err, errorx.ErrRefreshSignatureReplay) {
		t.Fatalf("expected replay error, got result=%v err=%v", secondResult, err)
	}
}

func signDevicePayloadForTest(t *testing.T, priv ed25519.PrivateKey, req *entity.RotateToken) string {
	t.Helper()
	payload := security.CanonicalRefreshPayload(req.JTI, req.IssuedAt, req.HTM, req.HTU, req.TokenHash, req.DeviceID)
	sum := sha256.Sum256([]byte(payload))
	sig := ed25519.Sign(priv, sum[:])
	return base64.RawURLEncoding.EncodeToString(sig)
}
