package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"iam/internal/config"
	"iam/internal/domain/entity"
	domainrepo "iam/internal/domain/repository"
	"iam/internal/security"
	"iam/pkg/errorx"
	"iam/pkg/id"
)

type AdminAuthService struct {
	repo    domainrepo.AdminAuthRepository
	secrets security.SecretProvider
	cfg     *config.Config
}

func NewAdminAuthService(
	repo domainrepo.AdminAuthRepository,
	secrets security.SecretProvider,
	cfg *config.Config,
) *AdminAuthService {
	return &AdminAuthService{
		repo:    repo,
		secrets: secrets,
		cfg:     cfg,
	}
}

func (s *AdminAuthService) EnsureBootstrapCredential(ctx context.Context) (*entity.AdminBootstrapResult, error) {
	if s == nil || s.repo == nil || s.secrets == nil {
		return &entity.AdminBootstrapResult{Created: false}, nil
	}

	hasAny, err := s.repo.HasAdminCredentials(ctx)
	if err != nil {
		return nil, err
	}
	if hasAny {
		return &entity.AdminBootstrapResult{Created: false}, nil
	}

	active, err := s.secrets.GetActive(security.SecretFamilyAdminAPI)
	if err != nil {
		return nil, err
	}
	rawToken, err := security.GenerateToken(256, active.Value)
	if err != nil {
		return nil, err
	}
	tokenHash, err := security.HashToken(rawToken, active.Value)
	if err != nil {
		return nil, err
	}

	// Generate 2FA: TOTP
	totpRes, err := security.GenerateTOTP("Aurora Cloud", "System Admin")
	if err != nil {
		return nil, err
	}
	encryptedTOTP, err := security.EncryptSecret(totpRes.Secret, s.masterKey())
	if err != nil {
		return nil, err
	}

	// Generate 2FA: Recovery Codes
	var recoveryPlain []string
	var mfaMethods []*entity.AdminMFAMethod
	now := time.Now().UTC()

	adminID, err := id.Generate()
	if err != nil {
		return nil, err
	}

	for i := 0; i < 10; i++ {
		code, err := security.GenerateRecoveryCode(12)
		if err != nil {
			return nil, err
		}
		recoveryPlain = append(recoveryPlain, code)

		methodID, err := id.Generate()
		if err != nil {
			return nil, err
		}
		mfaMethods = append(mfaMethods, &entity.AdminMFAMethod{
			ID:          methodID,
			AdminUserID: adminID,
			Method:      entity.AdminMFATypeRecovery,
			Status:      entity.AdminMFAStatusActive,
			CodeHash:    security.HashRecoveryCode(code),
			CreatedAt:   now,
			UpdatedAt:   now,
		})
	}

	// Add TOTP method
	totpMethodID, err := id.Generate()
	if err != nil {
		return nil, err
	}
	mfaMethods = append(mfaMethods, &entity.AdminMFAMethod{
		ID:              totpMethodID,
		AdminUserID:     adminID,
		Method:          entity.AdminMFATypeTOTP,
		Status:          entity.AdminMFAStatusActive,
		SecretEncrypted: encryptedTOTP,
		CreatedAt:       now,
		UpdatedAt:       now,
	})

	credentialID, err := id.Generate()
	if err != nil {
		return nil, err
	}

	admin := &entity.AdminUser{
		ID:          adminID,
		DisplayName: "System Admin",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	credential := &entity.AdminAPICredential{
		ID:          credentialID,
		AdminUserID: adminID,
		TokenHash:   tokenHash,
		ExpiresAt:   now.AddDate(10, 0, 0),
		CreatedAt:   now,
		UpdatedAt:   now,
		LastUsedAt:  &now,
	}

	if err := s.repo.CreateBootstrapAdmin(ctx, admin, credential, mfaMethods); err != nil {
		return nil, err
	}

	return &entity.AdminBootstrapResult{
		AdminKey:      rawToken,
		TOTPSecret:    totpRes.Secret,
		RecoveryCodes: recoveryPlain,
		Created:       true,
	}, nil
}

func (s *AdminAuthService) Login(ctx context.Context, input entity.AdminLoginInput) (*entity.AdminLoginResult, error) {
	if s == nil || s.repo == nil || s.secrets == nil {
		return nil, errorx.ErrAdminAuthInvalid
	}

	now := time.Now().UTC()
	input.AdminKey = strings.TrimSpace(input.AdminKey)
	input.ClientIP = strings.TrimSpace(input.ClientIP)
	input.UserAgent = strings.TrimSpace(input.UserAgent)
	if input.AdminKey == "" {
		return nil, errorx.ErrAdminAuthInvalid
	}

	credential, admin, err := s.credentialFromAdminKey(ctx, input.AdminKey, now)
	if err != nil || !credentialUsable(credential, now) || !adminUsable(admin) {
		s.audit(ctx, "admin_login_failed", 2, input.ClientIP, input.UserAgent, "", nil)
		return nil, errorx.ErrAdminAuthInvalid
	}

	loginDevice, trusted, err := s.validLoginDevice(ctx, input, admin, credential, now)
	if err != nil {
		s.audit(ctx, "admin_device_secret_mismatch", 4, input.ClientIP, input.UserAgent, input.DeviceID, map[string]any{
			"admin_user_id": admin.ID,
			"credential_id": credential.ID,
		})
		return nil, errorx.ErrAdminDeviceInvalid
	}

	if !trusted {
		ok, err := s.verifyMFA(ctx, admin.ID, input.TwoFactorCode)
		if err != nil || !ok {
			return nil, errorx.ErrAdminAuthInvalid
		}
	}

	device := loginDevice
	deviceSecret := strings.TrimSpace(input.DeviceSecret)
	deviceExpiresAt := now.Add(s.cfg.Security.AdminSessionTTL)
	if device == nil {
		device, deviceSecret, err = s.createDevice(ctx, admin, credential, input, now)
		if err != nil {
			return nil, err
		}
		s.audit(ctx, "admin_device_created", 1, input.ClientIP, input.UserAgent, device.ID, map[string]any{
			"admin_user_id": admin.ID,
			"credential_id": credential.ID,
		})
	} else {
		if input.TrustDevice {
			trustedUntil := now.Add(s.cfg.Security.AdminTrustedDeviceTTL)
			if err := s.repo.TrustDevice(ctx, device.ID, trustedUntil); err != nil {
				return nil, err
			}
			device.TrustedUntil = &trustedUntil
		}
		if err := s.repo.TouchDevice(ctx, device.ID, input.ClientIP, now); err != nil {
			return nil, err
		}
		if device.TrustedUntil != nil {
			deviceExpiresAt = *device.TrustedUntil
		}
	}

	sessionToken, session, err := s.createSession(ctx, admin, credential, device, now)
	if err != nil {
		return nil, err
	}

	s.audit(ctx, "admin_login_success", 1, input.ClientIP, input.UserAgent, device.ID, map[string]any{
		"admin_user_id": admin.ID,
		"credential_id": credential.ID,
	})
	s.audit(ctx, "admin_session_created", 1, input.ClientIP, input.UserAgent, device.ID, map[string]any{
		"admin_user_id": admin.ID,
		"credential_id": credential.ID,
		"session_id":    session.ID,
	})

	return &entity.AdminLoginResult{
		Admin:            admin,
		SessionID:        session.ID,
		SessionToken:     sessionToken,
		SessionExpiresAt: session.ExpiresAt,
		DeviceID:         device.ID,
		DeviceSecret:     deviceSecret,
		DeviceExpiresAt:  deviceExpiresAt,
	}, nil
}

func (s *AdminAuthService) AuthorizeSession(ctx context.Context, input entity.AdminSessionAuthInput) (*entity.AdminSessionContext, error) {
	if s == nil || s.repo == nil || s.secrets == nil {
		return nil, errorx.ErrAdminSessionInvalid
	}

	now := time.Now().UTC()
	input.SessionToken = strings.TrimSpace(input.SessionToken)
	input.DeviceID = strings.TrimSpace(input.DeviceID)
	input.DeviceSecret = strings.TrimSpace(input.DeviceSecret)
	input.ClientIP = strings.TrimSpace(input.ClientIP)
	input.UserAgent = strings.TrimSpace(input.UserAgent)
	if input.SessionToken == "" || input.DeviceID == "" || input.DeviceSecret == "" {
		return nil, errorx.ErrAdminSessionInvalid
	}

	session, admin, credential, device, err := s.sessionFromToken(ctx, input.SessionToken, now)
	if err != nil || !sessionUsable(session, now) || !adminUsable(admin) || !credentialUsable(credential, now) || !deviceUsable(device) {
		return nil, errorx.ErrAdminSessionInvalid
	}
	if session.DeviceID != input.DeviceID || device.ID != input.DeviceID {
		_ = s.repo.RevokeSession(ctx, session.SessionTokenHash, now)
		return nil, errorx.ErrAdminDeviceInvalid
	}

	if !s.verifyTokenHash(input.DeviceSecret, device.DeviceSecretHash) {
		_ = s.repo.MarkDeviceSuspicious(ctx, device.ID)
		_ = s.repo.RevokeSession(ctx, session.SessionTokenHash, now)
		s.audit(ctx, "admin_device_secret_mismatch", 4, input.ClientIP, input.UserAgent, input.DeviceID, map[string]any{
			"admin_user_id": admin.ID,
			"credential_id": credential.ID,
			"session_id":    session.ID,
		})
		return nil, errorx.ErrAdminDeviceInvalid
	}
	if err := s.repo.TouchDevice(ctx, device.ID, input.ClientIP, now); err != nil {
		return nil, err
	}

	return &entity.AdminSessionContext{
		AdminUserID:  admin.ID,
		DisplayName:  admin.DisplayName,
		CredentialID: credential.ID,
		DeviceID:     device.ID,
		SessionID:    session.ID,
		ExpiresAt:    session.ExpiresAt,
	}, nil
}

func (s *AdminAuthService) Logout(ctx context.Context, sessionToken string) error {
	if s == nil || s.repo == nil || s.secrets == nil {
		return nil
	}
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return nil
	}

	now := time.Now().UTC()
	for _, version := range s.secretCandidates() {
		sessionHash, err := security.HashToken(sessionToken, version.Value)
		if err != nil {
			continue
		}
		session, _, _, device, err := s.repo.GetSessionByHash(ctx, sessionHash, now)
		if err != nil || session == nil {
			continue
		}
		if err := s.repo.RevokeSession(ctx, sessionHash, now); err != nil {
			return err
		}
		deviceID := ""
		if device != nil {
			deviceID = device.ID
		}
		s.audit(ctx, "admin_logout", 1, "", "", deviceID, map[string]any{"session_id": session.ID})
		return nil
	}
	return nil
}

func (s *AdminAuthService) credentialFromAdminKey(ctx context.Context, adminKey string, now time.Time) (*entity.AdminAPICredential, *entity.AdminUser, error) {
	for _, version := range s.secretCandidates() {
		tokenHash, err := security.HashToken(adminKey, version.Value)
		if err != nil {
			continue
		}
		credential, admin, err := s.repo.GetCredentialByHash(ctx, tokenHash, now)
		if err == nil && credential != nil && admin != nil {
			return credential, admin, nil
		}
		if err != nil && !errors.Is(err, errorx.ErrAdminAuthInvalid) {
			return nil, nil, err
		}
	}
	return nil, nil, errorx.ErrAdminAuthInvalid
}

func (s *AdminAuthService) sessionFromToken(ctx context.Context, token string, now time.Time) (*entity.AdminSession, *entity.AdminUser, *entity.AdminAPICredential, *entity.AdminDevice, error) {
	for _, version := range s.secretCandidates() {
		sessionHash, err := security.HashToken(token, version.Value)
		if err != nil {
			continue
		}
		session, admin, credential, device, err := s.repo.GetSessionByHash(ctx, sessionHash, now)
		if err == nil && session != nil && admin != nil && credential != nil && device != nil {
			return session, admin, credential, device, nil
		}
		if err != nil && !errors.Is(err, errorx.ErrAdminSessionInvalid) {
			return nil, nil, nil, nil, err
		}
	}
	return nil, nil, nil, nil, errorx.ErrAdminSessionInvalid
}

func (s *AdminAuthService) validLoginDevice(ctx context.Context, input entity.AdminLoginInput, admin *entity.AdminUser, credential *entity.AdminAPICredential, now time.Time) (*entity.AdminDevice, bool, error) {
	deviceID := strings.TrimSpace(input.DeviceID)
	deviceSecret := strings.TrimSpace(input.DeviceSecret)
	if deviceID == "" || deviceSecret == "" {
		return nil, false, nil
	}

	device, err := s.repo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, false, nil
	}
	if device == nil || device.AdminUserID != admin.ID || device.CredentialID != credential.ID || !deviceUsable(device) {
		return nil, false, nil
	}
	if !s.verifyTokenHash(deviceSecret, device.DeviceSecretHash) {
		_ = s.repo.MarkDeviceSuspicious(ctx, device.ID)
		return nil, false, errorx.ErrAdminDeviceInvalid
	}
	return device, device.TrustedUntil != nil && device.TrustedUntil.After(now), nil
}

func (s *AdminAuthService) verifyMFA(ctx context.Context, adminUserID, code string) (bool, error) {
	methods, err := s.repo.ListMFAMethods(ctx, adminUserID)
	if err != nil {
		return false, err
	}
	hasActive := false
	code = strings.TrimSpace(code)
	for _, method := range methods {
		if method == nil || method.Status != entity.AdminMFAStatusActive {
			continue
		}
		hasActive = true
		if code == "" {
			continue
		}
		switch method.Method {
		case entity.AdminMFATypeTOTP:
			secret, err := security.DecryptSecret(method.SecretEncrypted, s.masterKey())
			if err != nil {
				continue
			}
			if security.ValidateTOTP(code, secret) {
				return true, nil
			}
		case entity.AdminMFATypeRecovery:
			if security.HashRecoveryCode(code) == strings.TrimSpace(method.CodeHash) {
				return true, nil
			}
		}
	}
	if !hasActive {
		return true, nil
	}
	return false, nil
}

func (s *AdminAuthService) createDevice(ctx context.Context, admin *entity.AdminUser, credential *entity.AdminAPICredential, input entity.AdminLoginInput, now time.Time) (*entity.AdminDevice, string, error) {
	active, err := s.secrets.GetActive(security.SecretFamilyAdminAPI)
	if err != nil {
		return nil, "", err
	}
	deviceID, err := id.Generate()
	if err != nil {
		return nil, "", err
	}
	deviceSecret, err := security.GenerateToken(128, active.Value)
	if err != nil {
		return nil, "", err
	}
	secretHash, err := security.HashToken(deviceSecret, active.Value)
	if err != nil {
		return nil, "", err
	}
	var trustedUntil *time.Time
	if input.TrustDevice {
		v := now.Add(s.cfg.Security.AdminTrustedDeviceTTL)
		trustedUntil = &v
	}
	device := &entity.AdminDevice{
		ID:               deviceID,
		AdminUserID:      admin.ID,
		CredentialID:     credential.ID,
		DeviceSecretHash: secretHash,
		Status:           entity.AdminDeviceStatusActive,
		TrustedUntil:     trustedUntil,
		LastSeenAt:       now,
		LastSeenIP:       input.ClientIP,
		UserAgent:        input.UserAgent,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.repo.CreateDevice(ctx, device); err != nil {
		return nil, "", err
	}
	return device, deviceSecret, nil
}

func (s *AdminAuthService) createSession(ctx context.Context, admin *entity.AdminUser, credential *entity.AdminAPICredential, device *entity.AdminDevice, now time.Time) (string, *entity.AdminSession, error) {
	active, err := s.secrets.GetActive(security.SecretFamilyAdminAPI)
	if err != nil {
		return "", nil, err
	}
	sessionID, err := id.Generate()
	if err != nil {
		return "", nil, err
	}
	sessionToken, err := security.GenerateToken(128, active.Value)
	if err != nil {
		return "", nil, err
	}
	sessionHash, err := security.HashToken(sessionToken, active.Value)
	if err != nil {
		return "", nil, err
	}
	session := &entity.AdminSession{
		ID:               sessionID,
		AdminUserID:      admin.ID,
		CredentialID:     credential.ID,
		DeviceID:         device.ID,
		SessionTokenHash: sessionHash,
		Status:           entity.AdminSessionStatusActive,
		ExpiresAt:        now.Add(s.cfg.Security.AdminSessionTTL),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.repo.CreateSession(ctx, session); err != nil {
		return "", nil, err
	}
	return sessionToken, session, nil
}

func (s *AdminAuthService) verifyTokenHash(token, storedHash string) bool {
	storedHash = strings.TrimSpace(storedHash)
	if storedHash == "" {
		return false
	}
	for _, version := range s.secretCandidates() {
		hash, err := security.HashToken(token, version.Value)
		if err == nil && hash == storedHash {
			return true
		}
	}
	return false
}

func (s *AdminAuthService) secretCandidates() []security.SecretVersion {
	if s == nil || s.secrets == nil {
		return nil
	}
	candidates, err := s.secrets.GetCandidates(security.SecretFamilyAdminAPI)
	if err == nil && len(candidates) > 0 {
		return candidates
	}
	active, err := s.secrets.GetActive(security.SecretFamilyAdminAPI)
	if err != nil || strings.TrimSpace(active.Value) == "" {
		return nil
	}
	return []security.SecretVersion{active}
}

func (s *AdminAuthService) audit(ctx context.Context, action string, risk int16, ipAddress, userAgent, deviceID string, metadata map[string]any) {
	if s == nil || s.repo == nil {
		return
	}
	auditID, err := id.Generate()
	if err != nil {
		return
	}
	var raw *json.RawMessage
	if len(metadata) > 0 {
		payload, err := json.Marshal(metadata)
		if err == nil {
			msg := json.RawMessage(payload)
			raw = &msg
		}
	}
	_ = s.repo.InsertAudit(ctx, &entity.AuditLog{
		ID:        auditID,
		Action:    action,
		RiskLevel: risk,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		DeviceID:  deviceID,
		Metadata:  raw,
		CreatedAt: time.Now().UTC(),
	})
}

func (s *AdminAuthService) masterKey() string {
	if s == nil || s.cfg == nil {
		return ""
	}
	return s.cfg.Security.MasterKey
}

func credentialUsable(v *entity.AdminAPICredential, now time.Time) bool {
	if v == nil || v.Suspicious {
		return false
	}
	return v.ExpiresAt.IsZero() || v.ExpiresAt.After(now)
}

func adminUsable(v *entity.AdminUser) bool {
	return v != nil
}

func deviceUsable(v *entity.AdminDevice) bool {
	return v != nil && v.Status == entity.AdminDeviceStatusActive && !v.Suspicious
}

func sessionUsable(v *entity.AdminSession, now time.Time) bool {
	if v == nil || v.Status != entity.AdminSessionStatusActive {
		return false
	}
	if v.RevokedAt != nil {
		return false
	}
	return v.ExpiresAt.After(now)
}
