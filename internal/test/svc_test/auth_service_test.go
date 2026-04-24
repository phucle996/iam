package svc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
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

// Replicate unexported constants from service package for testing side effects in Redis.
const (
	resetTokenPrefix = "iam:ott:reset:"
)

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func buildAbsoluteLink(baseURL, path string, query url.Values) string {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		base = "http://localhost:8080"
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	base = strings.TrimRight(base, "/")
	path = "/" + strings.TrimLeft(path, "/")
	link := base + path
	if len(query) == 0 {
		return link
	}
	return link + "?" + query.Encode()
}

func TestBuildAbsoluteLink(t *testing.T) {
	t.Parallel()

	got := buildAbsoluteLink("https://controlplane.example.com/app/", "/api/v1/auth/activate", url.Values{
		"token": []string{"abc123"},
	})
	want := "https://controlplane.example.com/app/api/v1/auth/activate?token=abc123"
	if got != want {
		t.Fatalf("unexpected link\nwant: %s\ngot:  %s", want, got)
	}

	got = buildAbsoluteLink("controlplane.example.com", "reset-password", url.Values{
		"token": []string{"abc123"},
	})
	want = "http://controlplane.example.com/reset-password?token=abc123"
	if got != want {
		t.Fatalf("unexpected normalized link\nwant: %s\ngot:  %s", want, got)
	}
}

func TestAuthServiceResetPasswordRevokesSessions(t *testing.T) {
	ctx := context.Background()

	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})

	rawToken := "reset-token-123"
	key := resetTokenPrefix + tokenDigest(rawToken)
	if err := client.HSet(ctx, key, map[string]any{
		"user_id":    "user-1",
		"email":      "user@example.com",
		"full_name":  "User Test",
		"expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}).Err(); err != nil {
		t.Fatalf("seed reset token: %v", err)
	}

	repo := &stubUserRepo{}
	tokenSvc := &stubTokenService{}
	svc := service.NewAuthService(
		repo,
		nil,      // deviceSvc
		tokenSvc,
		nil,      // mfaSvc
		nil,      // adminSvc
		client,
		&config.Config{
			Security: config.SecurityCfg{
				OneTimeTokenTTL: time.Hour,
			},
		},
		&fakeSecretProvider{},
	)

	if err := svc.ResetPassword(ctx, rawToken, "new-password-123"); err != nil {
		t.Fatalf("reset password: %v", err)
	}

	if repo.updatedUserID != "user-1" {
		t.Fatalf("expected password update for user-1, got %q", repo.updatedUserID)
	}
	if repo.updatedPasswordHash == "" {
		t.Fatalf("expected password hash to be stored")
	}
	ok, err := security.VerifyPassword(repo.updatedPasswordHash, "new-password-123")
	if err != nil {
		t.Fatalf("verify password hash: %v", err)
	}
	if !ok {
		t.Fatalf("expected stored password hash to match the new password")
	}
	if tokenSvc.revokeAllUserID != "user-1" {
		t.Fatalf("expected refresh tokens to be revoked for user-1, got %q", tokenSvc.revokeAllUserID)
	}
	if mr.Exists(key) {
		t.Fatalf("expected reset token to be consumed")
	}
}

func TestAuthServiceLoginBindsDeviceWithProvidedFingerprintAndKey(t *testing.T) {
	ctx := context.Background()

	passwordHash, err := security.HashPassword("password123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	pub, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa keypair: %v", err)
	}

	userRepo := &stubUserRepo{
		usersByUsername: map[string]*entity.User{
			"user-1": {
				ID:           "user-1",
				Username:     "user-1",
				PasswordHash: passwordHash,
				Status:       "active",
				SecurityLevel: 4,
			},
		},
	}
	deviceRepo := &stubDeviceRepo{}
	deviceSvc := service.NewDeviceService(deviceRepo)
	tokenSvc := &stubTokenService{}
	svc := service.NewAuthService(
		userRepo,
		deviceSvc,
		tokenSvc,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	result, err := svc.Login(ctx, "user-1", "password123", "install-abc", encodeECDSAP256PublicKeyPEM(&pub.PublicKey), "ES256")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if !tokenSvc.issueAfterLoginCalled {
		t.Fatalf("expected access/refresh token issuance to run")
	}
	if tokenSvc.issueAfterLoginUserID != "user-1" {
		t.Fatalf("expected tokens for user-1, got %q", tokenSvc.issueAfterLoginUserID)
	}
	if deviceRepo.device == nil {
		t.Fatalf("expected device to be created")
	}
	if deviceRepo.device.Fingerprint != "install-abc" {
		t.Fatalf("expected client fingerprint to be stored, got %q", deviceRepo.device.Fingerprint)
	}
	if deviceRepo.device.KeyAlgorithm != security.AlgECDSAP256 {
		t.Fatalf("expected key algorithm to normalize to %q, got %q", security.AlgECDSAP256, deviceRepo.device.KeyAlgorithm)
	}
	if deviceRepo.device.DevicePublicKey == "" {
		t.Fatalf("expected device public key to be stored")
	}
	if result.DeviceID != deviceRepo.device.ID {
		t.Fatalf("expected login result device id %q, got %q", deviceRepo.device.ID, result.DeviceID)
	}
}

func TestAuthServiceWhoAmIReturnsFlatSession(t *testing.T) {
	ctx := context.Background()

	userRepo := &stubUserRepo{
		whoAmiByUserID: map[string]*entity.WhoAmI{
			"user-1": {
				UserID:         "user-1",
				Username:       "user-1",
				Email:          "user@example.com",
				Phone:          "123456789",
				FullName:       "User One",
				AvatarURL:      "https://cdn.example.com/avatar.png",
				Bio:            "hello",
				Company:        "",
				ReferralSource: "",
				JobFunction:    "",
				Country:        "",
				Status:         "active",
				OnBoarding:     false,
				Roles:          []string{"admin"},
				Permissions:    []string{"iam:users:read", "iam:users:write"},
			},
		},
	}
	svc := service.NewAuthService(userRepo, nil, nil, nil, nil, nil, nil, nil)

	result, err := svc.WhoAmI(ctx, "user-1")
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if result == nil {
		t.Fatalf("expected flat whoami result, got %#v", result)
	}
	if result.UserID != "user-1" {
		t.Fatalf("expected user id user-1, got %q", result.UserID)
	}
	if len(result.Roles) != 1 || result.Roles[0] != "admin" {
		t.Fatalf("expected admin role in whoami, got %#v", result.Roles)
	}
	if len(result.Permissions) != 2 {
		t.Fatalf("expected permissions from snapshot, got %#v", result.Permissions)
	}
	if result.Phone != "123456789" {
		t.Fatalf("expected phone in whoami result, got %q", result.Phone)
	}
	if result.FullName != "User One" {
		t.Fatalf("expected full name in whoami result, got %q", result.FullName)
	}
	if result.AvatarURL != "https://cdn.example.com/avatar.png" {
		t.Fatalf("expected avatar url in whoami result, got %q", result.AvatarURL)
	}
	if userRepo.whoAmiCalls != 1 {
		t.Fatalf("expected exactly one whoami repo call, got %d", userRepo.whoAmiCalls)
	}
}

func TestAuthServiceAdminAPIKeyLogin(t *testing.T) {
	ctx := context.Background()

	svc := service.NewAuthService(nil, nil, nil, nil, &stubAdminAPITokenService{valid: true}, nil, nil, nil)

	if err := svc.AdminAPIKeyLogin(ctx, "admin-key-1"); err != nil {
		t.Fatalf("expected valid admin api key login, got error: %v", err)
	}

	svc = service.NewAuthService(nil, nil, nil, nil, &stubAdminAPITokenService{valid: false}, nil, nil, nil)
	if err := svc.AdminAPIKeyLogin(ctx, "wrong-key"); err != errorx.ErrAdminAPIKeyInvalid {
		t.Fatalf("expected ErrAdminAPIKeyInvalid, got %v", err)
	}
}
