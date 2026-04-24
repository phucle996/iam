package svc_test

import (
	"context"
	"testing"
	"time"

	"iam/internal/config"
	"iam/internal/domain/entity"
	"iam/internal/security"
	"iam/internal/service"

	"github.com/pquerna/otp/totp"
)

func TestMfaServiceEnrollAndConfirmTOTP(t *testing.T) {
	ctx := context.Background()

	const masterKey = "12345678901234567890123456789012"

	userRepo := &stubUserRepo{
		usersByID: map[string]*entity.User{
			"user-1": {
				ID:    "user-1",
				Email: "user@example.com",
			},
		},
	}
	mfaRepo := &stubMfaRepo{}
	svc := service.NewMfaService(
		mfaRepo,
		userRepo,
		nil, // rdb
		&config.Config{
			Security: config.SecurityCfg{
				MasterKey: masterKey,
			},
		},
	)

	settingID, provisioningURI, err := svc.EnrollTOTP(ctx, "user-1", "Pixel 9")
	if err != nil {
		t.Fatalf("enroll totp: %v", err)
	}
	if settingID == "" {
		t.Fatalf("expected a setting id")
	}
	if provisioningURI == "" {
		t.Fatalf("expected provisioning uri")
	}
	if len(provisioningURI) < len("otpauth://") || provisioningURI[:10] != "otpauth://" {
		t.Fatalf("expected otpauth provisioning uri, got %q", provisioningURI)
	}
	if mfaRepo.mfa == nil {
		t.Fatalf("expected MFA setting to be persisted")
	}
	if mfaRepo.mfa.SecretEncrypted == "" {
		t.Fatalf("expected encrypted secret to be stored")
	}

	secret, err := security.DecryptSecret(mfaRepo.mfa.SecretEncrypted, masterKey)
	if err != nil {
		t.Fatalf("decrypt totp secret: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}

	if err := svc.ConfirmTOTP(ctx, "user-1", settingID, code); err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	if mfaRepo.mfa == nil || !mfaRepo.mfa.IsEnabled {
		t.Fatalf("expected totp method to be enabled after confirmation")
	}
}
