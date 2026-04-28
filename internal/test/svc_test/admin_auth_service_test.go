package svc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"iam/internal/config"
	"iam/internal/domain/entity"
	"iam/internal/security"
	"iam/internal/service"
	"iam/pkg/errorx"
)

type adminAuthRepoStub struct {
	admin        *entity.AdminUser
	credential   *entity.AdminAPICredential
	device       *entity.AdminDevice
	session      *entity.AdminSession
	mfaMethods   []*entity.AdminMFAMethod
	auditActions []string

	createdDeviceSecretHash string
	createdSessionHash      string
	revokedSessionHash      string
	markedSuspiciousID      string
	disabledMFAMethodID     string
}

func (r *adminAuthRepoStub) HasAdminCredentials(ctx context.Context) (bool, error) {
	return r.credential != nil, nil
}

func (r *adminAuthRepoStub) CreateBootstrapAdmin(ctx context.Context, admin *entity.AdminUser, credential *entity.AdminAPICredential, mfaMethods []*entity.AdminMFAMethod) error {
	r.admin = admin
	r.credential = credential
	r.mfaMethods = mfaMethods
	return nil
}

func (r *adminAuthRepoStub) GetCredentialByHash(ctx context.Context, tokenHash string, now time.Time) (*entity.AdminAPICredential, *entity.AdminUser, error) {
	if r.credential == nil || r.admin == nil || r.credential.TokenHash != tokenHash {
		return nil, nil, errorx.ErrAdminAuthInvalid
	}
	return r.credential, r.admin, nil
}

func (r *adminAuthRepoStub) ListMFAMethods(ctx context.Context, adminUserID string) ([]*entity.AdminMFAMethod, error) {
	return r.mfaMethods, nil
}

func (r *adminAuthRepoStub) DisableMFAMethod(ctx context.Context, methodID string) error {
	r.disabledMFAMethodID = methodID
	for _, method := range r.mfaMethods {
		if method != nil && method.ID == methodID {
			method.Status = entity.AdminMFAStatusDisabled
		}
	}
	return nil
}

func (r *adminAuthRepoStub) GetDeviceByID(ctx context.Context, deviceID string) (*entity.AdminDevice, error) {
	if r.device == nil || r.device.ID != deviceID {
		return nil, errorx.ErrAdminDeviceInvalid
	}
	return r.device, nil
}

func (r *adminAuthRepoStub) CreateDevice(ctx context.Context, device *entity.AdminDevice) error {
	r.device = device
	r.createdDeviceSecretHash = device.DeviceSecretHash
	return nil
}

func (r *adminAuthRepoStub) TrustDevice(ctx context.Context, deviceID string, trustedUntil time.Time) error {
	if r.device != nil && r.device.ID == deviceID {
		r.device.TrustedUntil = &trustedUntil
	}
	return nil
}

func (r *adminAuthRepoStub) TouchDevice(ctx context.Context, deviceID, ip string, seenAt time.Time) error {
	if r.device != nil && r.device.ID == deviceID {
		r.device.LastSeenIP = ip
		r.device.LastSeenAt = seenAt
	}
	return nil
}

func (r *adminAuthRepoStub) MarkDeviceSuspicious(ctx context.Context, deviceID string) error {
	r.markedSuspiciousID = deviceID
	return nil
}

func (r *adminAuthRepoStub) CreateSession(ctx context.Context, session *entity.AdminSession) error {
	r.session = session
	r.createdSessionHash = session.SessionTokenHash
	return nil
}

func (r *adminAuthRepoStub) GetSessionByHash(ctx context.Context, sessionHash string, now time.Time) (*entity.AdminSession, *entity.AdminUser, *entity.AdminAPICredential, *entity.AdminDevice, error) {
	if r.session == nil || r.session.SessionTokenHash != sessionHash {
		return nil, nil, nil, nil, errorx.ErrAdminSessionInvalid
	}
	return r.session, r.admin, r.credential, r.device, nil
}

func (r *adminAuthRepoStub) RevokeSession(ctx context.Context, sessionHash string, revokedAt time.Time) error {
	r.revokedSessionHash = sessionHash
	if r.session != nil && r.session.SessionTokenHash == sessionHash {
		r.session.Status = entity.AdminSessionStatusRevoked
	}
	return nil
}

func (r *adminAuthRepoStub) InsertAudit(ctx context.Context, audit *entity.AuditLog) error {
	if audit != nil {
		r.auditActions = append(r.auditActions, audit.Action)
	}
	return nil
}

func TestAdminAuthServiceLoginCreatesSessionAndDeviceCookies(t *testing.T) {
	ctx := context.Background()
	secret := "12345678901234567890123456789012"
	rawAdminKey := "adm_live_test"
	tokenHash, err := security.HashToken(rawAdminKey, secret)
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}

	repo := &adminAuthRepoStub{
		admin: &entity.AdminUser{
			ID:          "admin-1",
			DisplayName: "System Admin",
		},
		credential: &entity.AdminAPICredential{
			ID:          "cred-1",
			AdminUserID: "admin-1",
			TokenHash:   tokenHash,
			ExpiresAt:   time.Now().UTC().Add(time.Hour),
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
			LastUsedAt:  nil,
			Suspicious:  false,
		},
	}
	svc := service.NewAdminAuthService(repo, &fakeSecretProvider{active: security.SecretVersion{Value: secret}}, &config.Config{
		Security: config.SecurityCfg{
			AdminSessionTTL:        time.Hour,
			AdminTrustedDeviceTTL:  30 * 24 * time.Hour,
			AdminAllowedCIDRs:      []string{"10.0.0.0/8"},
			AdminMaxFailedAttempts: 5,
			AdminCredentialLockTTL: 15 * time.Minute,
		},
	})

	result, err := svc.Login(ctx, entity.AdminLoginInput{
		AdminKey:    rawAdminKey,
		TrustDevice: true,
		ClientIP:    "10.1.2.3",
		UserAgent:   "test-agent",
	})
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	if result.Admin == nil || result.Admin.ID != "admin-1" {
		t.Fatalf("expected admin identity, got %#v", result.Admin)
	}
	if result.SessionToken == "" || result.DeviceSecret == "" || result.DeviceID == "" {
		t.Fatalf("expected session and device token material, got %#v", result)
	}
	if repo.createdSessionHash == "" || repo.createdDeviceSecretHash == "" {
		t.Fatalf("expected stored session/device hashes")
	}
	if repo.device.TrustedUntil == nil || !repo.device.TrustedUntil.After(time.Now().UTC()) {
		t.Fatalf("expected trusted device ttl, got %#v", repo.device.TrustedUntil)
	}
}

func TestAdminAuthServiceBlocksCIDROutsidePolicy(t *testing.T) {
	ctx := context.Background()
	secret := "12345678901234567890123456789012"
	rawAdminKey := "adm_live_test"
	tokenHash, err := security.HashToken(rawAdminKey, secret)
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}
	repo := &adminAuthRepoStub{
		admin: &entity.AdminUser{ID: "admin-1"},
		credential: &entity.AdminAPICredential{
			ID:          "cred-1",
			AdminUserID: "admin-1",
			TokenHash:   tokenHash,
			ExpiresAt:   time.Now().UTC().Add(time.Hour),
		},
	}
	svc := service.NewAdminAuthService(repo, &fakeSecretProvider{active: security.SecretVersion{Value: secret}}, &config.Config{
		Security: config.SecurityCfg{AdminAllowedCIDRs: []string{"10.0.0.0/8"}},
	})

	_, err = svc.Login(ctx, entity.AdminLoginInput{AdminKey: rawAdminKey, ClientIP: "192.168.1.10"})
	if !errors.Is(err, errorx.ErrAdminAuthInvalid) {
		t.Fatalf("expected generic admin auth failure, got %v", err)
	}
	if len(repo.auditActions) == 0 || repo.auditActions[0] != "admin_login_blocked_by_cidr" {
		t.Fatalf("expected cidr audit event, got %#v", repo.auditActions)
	}
}

func TestAdminAuthServiceConsumesRecoveryCode(t *testing.T) {
	ctx := context.Background()
	secret := "12345678901234567890123456789012"
	rawAdminKey := "adm_live_test"
	recoveryCode := "RECOVERY1234"
	tokenHash, err := security.HashToken(rawAdminKey, secret)
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}

	repo := &adminAuthRepoStub{
		admin: &entity.AdminUser{ID: "admin-1", DisplayName: "System Admin"},
		credential: &entity.AdminAPICredential{
			ID:          "cred-1",
			AdminUserID: "admin-1",
			TokenHash:   tokenHash,
			ExpiresAt:   time.Now().UTC().Add(time.Hour),
		},
		mfaMethods: []*entity.AdminMFAMethod{
			{
				ID:              "totp-1",
				AdminUserID:     "admin-1",
				Method:          entity.AdminMFATypeTOTP,
				Status:          entity.AdminMFAStatusActive,
				SecretEncrypted: "invalid-encrypted-secret",
			},
			{
				ID:          "recovery-1",
				AdminUserID: "admin-1",
				Method:      entity.AdminMFATypeRecovery,
				Status:      entity.AdminMFAStatusActive,
				CodeHash:    security.HashRecoveryCode(recoveryCode),
			},
		},
	}
	svc := service.NewAdminAuthService(repo, &fakeSecretProvider{active: security.SecretVersion{Value: secret}}, &config.Config{
		Security: config.SecurityCfg{
			AdminSessionTTL:       time.Hour,
			AdminTrustedDeviceTTL: 30 * 24 * time.Hour,
		},
	})

	if _, err := svc.Login(ctx, entity.AdminLoginInput{AdminKey: rawAdminKey, TwoFactorCode: recoveryCode, ClientIP: "127.0.0.1"}); err != nil {
		t.Fatalf("admin login with recovery code: %v", err)
	}
	if repo.disabledMFAMethodID != "recovery-1" {
		t.Fatalf("expected recovery code to be disabled, got %q", repo.disabledMFAMethodID)
	}

	_, err = svc.Login(ctx, entity.AdminLoginInput{AdminKey: rawAdminKey, TwoFactorCode: recoveryCode, ClientIP: "127.0.0.1"})
	if !errors.Is(err, errorx.ErrAdminAuthInvalid) {
		t.Fatalf("expected consumed recovery code to fail, got %v", err)
	}
}
