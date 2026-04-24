package repo_test

import (
	"context"
	"iam/internal/domain/entity"
	"iam/internal/repository"
	"iam/pkg/errorx"
	"errors"
	"testing"
	"time"
)

func TestTokenRepositoryCycle(t *testing.T) {
	db := mustOpenIAMRepositoryIntegrationDB(t)
	mustResetIAMState(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	userID := "token-user-1"
	deviceID := "token-device-1"
	mustExecIAM(t, db, `INSERT INTO users (id, username, email, phone, password_hash, security_level, status, status_reason, created_at, updated_at)
		VALUES ($1, 'token-user', 'token@example.com', NULL, 'hash', 2, 'active', '', NOW(), NOW())`, userID)
	mustExecIAM(t, db, `INSERT INTO devices (id, user_id, fingerprint, device_public_key, key_algorithm, created_at, updated_at)
		VALUES ($1, $2, 'fp-1', 'key-1', 'alg-1', NOW(), NOW())`, deviceID, userID)

	repo := repository.NewTokenRepository(db)

	token := &entity.RefreshToken{
		ID:        "rt-123",
		UserID:    userID,
		DeviceID:  deviceID,
		TokenHash: "hash-123",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		IsRevoked: false,
		CreatedAt: time.Now().UTC(),
	}

	if err := repo.Create(ctx, token); err != nil {
		t.Fatalf("create token: %v", err)
	}

	got, err := repo.GetByHash(ctx, "hash-123")
	if err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if got.ID != token.ID {
		t.Fatalf("expected ID %q, got %q", token.ID, got.ID)
	}

	ok, err := repo.ConsumeActive(ctx, token.ID)
	if err != nil {
		t.Fatalf("consume active: %v", err)
	}
	if !ok {
		t.Fatalf("expected consume active to return true for non-revoked token")
	}

	okAgain, err := repo.ConsumeActive(ctx, token.ID)
	if err != nil {
		t.Fatalf("consume active again: %v", err)
	}
	if okAgain {
		t.Fatalf("expected consume active to return false for already revoked/consumed token")
	}

	if err := repo.Revoke(ctx, token.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func TestTokenRepositoryCleanupExpired(t *testing.T) {
	db := mustOpenIAMRepositoryIntegrationDB(t)
	mustResetIAMState(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	userID := "cleanup-user"
	deviceID := "cleanup-device"
	mustExecIAM(t, db, `INSERT INTO users (id, username, email, phone, password_hash, security_level, status, status_reason, created_at, updated_at)
		VALUES ($1, 'cleanup-user', 'cleanup@example.com', NULL, 'hash', 2, 'active', '', NOW(), NOW())`, userID)
	mustExecIAM(t, db, `INSERT INTO devices (id, user_id, fingerprint, device_public_key, key_algorithm, created_at, updated_at)
		VALUES ($1, $2, 'fp-cleanup', 'key-cleanup', 'alg-1', NOW(), NOW())`, deviceID, userID)

	repo := repository.NewTokenRepository(db)

	expiredToken := &entity.RefreshToken{
		ID:        "expired-rt",
		UserID:    userID,
		DeviceID:  deviceID,
		TokenHash: "expired-hash",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
		IsRevoked: false,
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := repo.Create(ctx, expiredToken); err != nil {
		t.Fatalf("create expired token: %v", err)
	}

	deleted, err := repo.DeleteExpiredBatch(ctx, 10)
	if err != nil {
		t.Fatalf("delete expired batch: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted token, got %d", deleted)
	}

	_, err = repo.GetByHash(ctx, "expired-hash")
	if !errors.Is(err, errorx.ErrRefreshTokenInvalid) {
		t.Fatalf("expected not found after cleanup, got %v", err)
	}
}
