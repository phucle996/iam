package repo_test

import (
	"context"
	"controlplane/internal/domain/entity"
	"controlplane/internal/repository"
	"controlplane/pkg/errorx"
	"errors"
	"testing"
	"time"
)

func TestDeviceRepositoryCycle(t *testing.T) {
	db := mustOpenIAMRepositoryIntegrationDB(t)
	mustResetIAMState(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	userID := "device-user-1"
	mustExecIAM(t, db, `INSERT INTO users (id, username, email, phone, password_hash, security_level, status, status_reason, created_at, updated_at)
		VALUES ($1, 'device-user', 'device@example.com', NULL, 'hash', 2, 'active', '', NOW(), NOW())`, userID)

	repo := repository.NewDeviceRepository(db)

	device := &entity.Device{
		ID:              "dev-123",
		UserID:          userID,
		Fingerprint:     "fingerprint-123",
		DevicePublicKey: "pubkey-123",
		KeyAlgorithm:    "Ed25519",
		DeviceName:      "My Laptop",
		LastActiveAt:    time.Now().UTC(),
	}

	if err := repo.CreateDevice(ctx, device); err != nil {
		t.Fatalf("create device: %v", err)
	}

	got, err := repo.GetDeviceByFingerprint(ctx, userID, "fingerprint-123")
	if err != nil {
		t.Fatalf("get by fingerprint: %v", err)
	}
	if got.ID != device.ID {
		t.Fatalf("expected ID %q, got %q", device.ID, got.ID)
	}

	got.DeviceName = "UpdatedName"
	if err := repo.UpdateDevice(ctx, got); err != nil {
		t.Fatalf("update device: %v", err)
	}

	gotUpdated, _ := repo.GetDeviceByID(ctx, device.ID)
	if gotUpdated.DeviceName != "UpdatedName" {
		t.Fatalf("expected updated device name")
	}

	if err := repo.DeleteDevice(ctx, device.ID); err != nil {
		t.Fatalf("delete device: %v", err)
	}

	_, err = repo.GetDeviceByID(ctx, device.ID)
	if !errors.Is(err, errorx.ErrDeviceNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}
