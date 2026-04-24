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

func TestMfaRepositoryCycle(t *testing.T) {
	db := mustOpenIAMRepositoryIntegrationDB(t)
	mustResetIAMState(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	userID := "mfa-user-1"
	mustExecIAM(t, db, `INSERT INTO users (id, username, email, phone, password_hash, security_level, status, status_reason, created_at, updated_at)
		VALUES ($1, 'mfa-user', 'mfa@example.com', NULL, 'hash', 2, 'active', '', NOW(), NOW())`, userID)

	repo := repository.NewMfaRepository(db)

	mfa := &entity.MfaSetting{
		ID:              "mfa-123",
		UserID:          userID,
		MfaType:         "totp",
		DeviceName:      "My Phone",
		SecretEncrypted: "encrypted-secret",
		IsPrimary:       true,
		IsEnabled:       true,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}

	if err := repo.Create(ctx, mfa); err != nil {
		t.Fatalf("create mfa: %v", err)
	}

	got, err := repo.GetByID(ctx, mfa.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.ID != mfa.ID {
		t.Fatalf("expected ID %q, got %q", mfa.ID, got.ID)
	}

	enabled, err := repo.ListEnabled(ctx, userID)
	if err != nil {
		t.Fatalf("list enabled: %v", err)
	}
	if len(enabled) != 1 {
		t.Fatalf("expected 1 enabled setting, got %d", len(enabled))
	}

	if err := repo.UpdateEnabled(ctx, mfa.ID, false); err != nil {
		t.Fatalf("update enabled: %v", err)
	}

	enabledAfter, _ := repo.ListEnabled(ctx, userID)
	if len(enabledAfter) != 0 {
		t.Fatalf("expected 0 enabled settings after disable")
	}

	codes := []*entity.RecoveryCode{
		{ID: "rc-1", UserID: userID, CodeHash: "hash-1", IsUsed: false},
		{ID: "rc-2", UserID: userID, CodeHash: "hash-2", IsUsed: false},
	}
	if err := repo.ReplaceRecoveryCodes(ctx, codes); err != nil {
		t.Fatalf("replace recovery codes: %v", err)
	}

	code, err := repo.GetUnusedRecoveryCode(ctx, userID, "hash-1")
	if err != nil {
		t.Fatalf("get recovery code: %v", err)
	}
	if code.ID != "rc-1" {
		t.Fatalf("expected code rc-1")
	}

	if err := repo.MarkRecoveryCodeUsed(ctx, code.ID); err != nil {
		t.Fatalf("mark used: %v", err)
	}

	_, err = repo.GetUnusedRecoveryCode(ctx, userID, "hash-1")
	if !errors.Is(err, errorx.ErrMfaCodeInvalid) {
		t.Fatalf("expected code invalid after use")
	}

	if err := repo.Delete(ctx, mfa.ID, userID); err != nil {
		t.Fatalf("delete mfa: %v", err)
	}
}
