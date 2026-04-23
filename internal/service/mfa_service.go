package service

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"controlplane/internal/config"
	"controlplane/internal/domain/entity"
	domainrepo "controlplane/internal/domain/repository"

	"controlplane/internal/security"
	"controlplane/pkg/errorx"
	"controlplane/pkg/id"

	"github.com/redis/go-redis/v9"
)

const (
	mfaChallengePrefix = "iam:mfa:challenge:"
	mfaChallengeTTL    = 3 * time.Minute

	mfaOTPLength       = 6
	recoveryCodeCount  = 10
	recoveryCodeLength = 8

	// Mail stream — same stream as register/reset flows.
	mfaMailStream = "stream:mail:outgoing"
)

var mfaValidMethods = []string{
	entity.MfaTypeTOTP,
	entity.MfaTypeSMS,
	entity.MfaTypeEmail,
	entity.MfaTypeRecovery,
}

// MfaService implements iam_domainsvc.MfaService.
type MfaService struct {
	mfaRepo  domainrepo.MfaRepository
	userRepo domainrepo.UserRepository
	rdb      *redis.Client
	cfg      *config.Config
}

func NewMfaService(
	mfaRepo domainrepo.MfaRepository,
	userRepo domainrepo.UserRepository,
	rdb *redis.Client,
	cfg *config.Config,
) *MfaService {
	return &MfaService{
		mfaRepo:  mfaRepo,
		userRepo: userRepo,
		rdb:      rdb,
		cfg:      cfg,
	}
}

// ── Login integration ─────────────────────────────────────────────────────────

// CheckAndChallenge is called by AuthService.Login after password verification.
// It checks for enabled MFA methods and, if found, creates a 3-min Redis challenge.
func (s *MfaService) CheckAndChallenge(ctx context.Context, userID, deviceID string) (bool, string, []string, error) {
	methods, err := s.mfaRepo.ListEnabled(ctx, userID)
	if err != nil {
		return false, "", nil, fmt.Errorf("mfa svc: list methods: %w", err)
	}
	if len(methods) == 0 {
		return false, "", nil, nil // no MFA — proceed with login
	}

	// Collect available method types (deduplicated).
	methodTypes := make([]string, 0, len(methods))
	seen := map[string]bool{}
	for _, m := range methods {
		if !seen[m.MfaType] {
			seen[m.MfaType] = true
			methodTypes = append(methodTypes, m.MfaType)
		}
	}
	// Always include recovery as a fallback.
	if !seen[entity.MfaTypeRecovery] {
		methodTypes = append(methodTypes, entity.MfaTypeRecovery)
	}

	challengeID, err := id.Generate()
	if err != nil {
		return false, "", nil, fmt.Errorf("mfa svc: gen challenge id: %w", err)
	}

	now := time.Now().UTC()

	// Store challenge in Redis as a hash.
	key := mfaChallengePrefix + challengeID
	payload := map[string]any{
		"user_id":           userID,
		"device_id":         deviceID,
		"available_methods": strings.Join(methodTypes, ","),
		"selected_method":   "",
		"otp_code":          "",
		"created_at":        now.Format(time.RFC3339Nano),
		"expires_at":        now.Add(mfaChallengeTTL).Format(time.RFC3339Nano),
	}

	pipe := s.rdb.TxPipeline()
	pipe.HSet(ctx, key, payload)
	pipe.Expire(ctx, key, mfaChallengeTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, "", nil, fmt.Errorf("mfa svc: store challenge: %w", err)
	}

	return true, challengeID, methodTypes, nil
}

// Verify validates the OTP/recovery code for a challenge.
// Returns userID + deviceID on success so AuthService can issue tokens.
func (s *MfaService) Verify(ctx context.Context, challengeID, method, code string) (string, string, error) {
	challengeID = strings.TrimSpace(challengeID)
	method = strings.TrimSpace(method)
	code = strings.TrimSpace(code)

	if challengeID == "" || method == "" || code == "" {
		return "", "", errorx.ErrMfaChallengeInvalid
	}

	// 1. Load challenge from Redis.
	key := mfaChallengePrefix + challengeID
	values, err := s.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return "", "", fmt.Errorf("mfa svc: load challenge: %w", err)
	}
	if len(values) == 0 {
		return "", "", errorx.ErrMfaChallengeNotFound
	}

	// 2. Belt-and-suspenders TTL check.
	if exp, ok := values["expires_at"]; ok {
		t, err := time.Parse(time.RFC3339Nano, exp)
		if err == nil && time.Now().UTC().After(t) {
			_ = s.rdb.Del(ctx, key).Err()
			return "", "", errorx.ErrMfaChallengeInvalid
		}
	}

	userID := values["user_id"]
	deviceID := values["device_id"]
	availableMethods := strings.Split(values["available_methods"], ",")

	// 3. Assert the method is allowed for this challenge.
	if !slices.Contains(availableMethods, method) {
		return "", "", errorx.ErrMfaMethodNotAllowed
	}

	// 4. Dispatch verification by method.
	switch method {
	case entity.MfaTypeTOTP:
		if err := s.verifyTOTP(ctx, userID, code); err != nil {
			return "", "", err
		}
	case entity.MfaTypeSMS, entity.MfaTypeEmail:
		if err := s.verifyOTP(values, code); err != nil {
			return "", "", err
		}
	case entity.MfaTypeRecovery:
		if err := s.verifyRecovery(ctx, userID, code); err != nil {
			return "", "", err
		}
	default:
		return "", "", errorx.ErrMfaMethodNotAllowed
	}

	// 5. Consume challenge — single-use.
	_ = s.rdb.Del(ctx, key).Err()

	return userID, deviceID, nil
}

// ── Enrollment ────────────────────────────────────────────────────────────────

func (s *MfaService) EnrollTOTP(ctx context.Context, userID, deviceName string) (string, string, error) {
	if s == nil || s.cfg == nil || s.userRepo == nil || s.mfaRepo == nil {
		return "", "", fmt.Errorf("mfa svc: configuration is nil")
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("mfa svc: get user: %w", err)
	}

	result, err := security.GenerateTOTP("Aurora Controlplane", user.Email)
	if err != nil {
		return "", "", fmt.Errorf("mfa svc: generate totp: %w", err)
	}

	settingID, err := id.Generate()
	if err != nil {
		return "", "", fmt.Errorf("mfa svc: gen id: %w", err)
	}

	encryptedSecret, err := security.EncryptSecret(result.Secret, s.cfg.Security.MasterKey)
	if err != nil {
		return "", "", fmt.Errorf("mfa svc: encrypt totp secret: %w", err)
	}

	setting := &entity.MfaSetting{
		ID:              settingID,
		UserID:          userID,
		MfaType:         entity.MfaTypeTOTP,
		DeviceName:      deviceName,
		IsPrimary:       false,
		SecretEncrypted: encryptedSecret,
		IsEnabled:       false, // enabled only after ConfirmTOTP
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}

	if err := s.mfaRepo.Create(ctx, setting); err != nil {
		return "", "", fmt.Errorf("mfa svc: create totp setting: %w", err)
	}

	return settingID, result.ProvisioningURI, nil
}

func (s *MfaService) ConfirmTOTP(ctx context.Context, userID, settingID, code string) error {
	if s == nil || s.cfg == nil || s.mfaRepo == nil {
		return fmt.Errorf("mfa svc: configuration is nil")
	}

	setting, err := s.mfaRepo.GetByID(ctx, settingID)
	if err != nil {
		return err
	}
	if setting.UserID != userID {
		return errorx.ErrMfaSettingNotFound
	}

	secret, err := s.decryptTOTPSecret(setting.SecretEncrypted)
	if err != nil {
		return err
	}

	if !security.ValidateTOTP(code, secret) {
		return errorx.ErrMfaCodeInvalid
	}

	return s.mfaRepo.UpdateEnabled(ctx, settingID, true)
}

func (s *MfaService) EnrollSMS(ctx context.Context, userID, deviceName string) (string, error) {
	return s.enrollDeliveryMethod(ctx, userID, deviceName, entity.MfaTypeSMS)
}

func (s *MfaService) EnrollEmail(ctx context.Context, userID, deviceName string) (string, error) {
	return s.enrollDeliveryMethod(ctx, userID, deviceName, entity.MfaTypeEmail)
}

func (s *MfaService) enrollDeliveryMethod(ctx context.Context, userID, deviceName, mfaType string) (string, error) {
	settingID, err := id.Generate()
	if err != nil {
		return "", fmt.Errorf("mfa svc: gen id: %w", err)
	}

	setting := &entity.MfaSetting{
		ID:         settingID,
		UserID:     userID,
		MfaType:    mfaType,
		DeviceName: deviceName,
		IsEnabled:  true, // SMS/email methods are active immediately
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	if err := s.mfaRepo.Create(ctx, setting); err != nil {
		return "", fmt.Errorf("mfa svc: create %s setting: %w", mfaType, err)
	}

	return settingID, nil
}

// ── Management ────────────────────────────────────────────────────────────────

func (s *MfaService) ListMethods(ctx context.Context, userID string) ([]*entity.MfaSetting, error) {
	return s.mfaRepo.ListEnabled(ctx, userID)
}

func (s *MfaService) EnableMethod(ctx context.Context, userID, settingID string) error {
	return s.assertOwnerAndUpdate(ctx, userID, settingID, true)
}

func (s *MfaService) DisableMethod(ctx context.Context, userID, settingID string) error {
	return s.assertOwnerAndUpdate(ctx, userID, settingID, false)
}

func (s *MfaService) assertOwnerAndUpdate(ctx context.Context, userID, settingID string, enabled bool) error {
	setting, err := s.mfaRepo.GetByID(ctx, settingID)
	if err != nil {
		return err
	}
	if setting.UserID != userID {
		return errorx.ErrMfaSettingNotFound
	}
	return s.mfaRepo.UpdateEnabled(ctx, settingID, enabled)
}

func (s *MfaService) DeleteMethod(ctx context.Context, userID, settingID string) error {
	return s.mfaRepo.Delete(ctx, settingID, userID)
}

func (s *MfaService) SetPrimaryMethod(ctx context.Context, userID, settingID string) error {
	// Ownership verified inside SetPrimary via user_id filter in SQL.
	return s.mfaRepo.SetPrimary(ctx, userID, settingID)
}

// ── Recovery Codes ────────────────────────────────────────────────────────────

func (s *MfaService) GenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	plainCodes := make([]string, recoveryCodeCount)
	entities := make([]*entity.RecoveryCode, recoveryCodeCount)

	for i := 0; i < recoveryCodeCount; i++ {
		raw, err := security.GenerateRecoveryCode(recoveryCodeLength)
		if err != nil {
			return nil, fmt.Errorf("mfa svc: gen recovery code: %w", err)
		}
		plainCodes[i] = raw

		codeID, err := id.Generate()
		if err != nil {
			return nil, fmt.Errorf("mfa svc: gen code id: %w", err)
		}

		entities[i] = &entity.RecoveryCode{
			ID:        codeID,
			UserID:    userID,
			CodeHash:  security.HashRecoveryCode(raw),
			IsUsed:    false,
			CreatedAt: time.Now().UTC(),
		}
	}

	if err := s.mfaRepo.ReplaceRecoveryCodes(ctx, entities); err != nil {
		return nil, err
	}

	return plainCodes, nil
}

// ── OTP delivery ──────────────────────────────────────────────────────────────

// SendOTP generates a 6-digit OTP, stores it in the challenge hash, and
// enqueues a delivery job (email or SMS stream payload).
func (s *MfaService) SendOTP(ctx context.Context, challengeID, method string) error {
	if s == nil || s.rdb == nil {
		return errorx.ErrMfaChallengeNotFound
	}

	key := mfaChallengePrefix + challengeID
	values, err := s.rdb.HGetAll(ctx, key).Result()
	if err != nil || len(values) == 0 {
		return errorx.ErrMfaChallengeNotFound
	}

	userID := values["user_id"]
	if userID == "" {
		return errorx.ErrMfaChallengeNotFound
	}

	// Generate OTP via security package.
	otpCode, err := security.GenerateOTP(mfaOTPLength)
	if err != nil {
		return fmt.Errorf("mfa svc: gen otp: %w", err)
	}

	// Store SHA-256 hash in challenge (never the plaintext).
	otpHash := security.HashOTP(otpCode)
	pipe := s.rdb.TxPipeline()
	pipe.HSet(ctx, key, "otp_code", otpHash, "selected_method", method)
	pipe.Expire(ctx, key, mfaChallengeTTL) // refresh TTL on resend
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("mfa svc: store otp: %w", err)
	}

	// Load user for delivery details.
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("mfa svc: get user for otp delivery: %w", err)
	}

	now := time.Now().UTC()
	payload := map[string]any{
		"type":         "mfa_otp",
		"sub_type":     method,
		"user_id":      userID,
		"email":        user.Email,
		"phone":        user.Phone,
		"otp_code":     otpCode, // plaintext sent to delivery worker
		"template_key": "mfa-otp",
		"created_at":   now.Format(time.RFC3339Nano),
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("mfa svc: marshal otp payload: %w", err)
	}

	return s.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: mfaMailStream,
		Values: map[string]any{
			"type":    "mfa_otp",
			"payload": string(raw),
		},
	}).Err()
}

// ── private verifiers ─────────────────────────────────────────────────────────

func (s *MfaService) verifyTOTP(ctx context.Context, userID, code string) error {
	setting, err := s.mfaRepo.GetByUserAndType(ctx, userID, entity.MfaTypeTOTP)
	if err != nil {
		return errorx.ErrMfaCodeInvalid
	}

	secret, err := s.decryptTOTPSecret(setting.SecretEncrypted)
	if err != nil {
		return err
	}

	if !security.ValidateTOTP(code, secret) {
		return errorx.ErrMfaCodeInvalid
	}
	return nil
}

func (s *MfaService) verifyOTP(challengeValues map[string]string, code string) error {
	storedHash := challengeValues["otp_code"]
	if storedHash == "" {
		return errorx.ErrMfaChallengeNotFound
	}
	if !security.VerifyOTP(strings.TrimSpace(code), storedHash) {
		return errorx.ErrMfaCodeInvalid
	}
	return nil
}

func (s *MfaService) verifyRecovery(ctx context.Context, userID, code string) error {
	hash := security.HashRecoveryCode(code)
	rc, err := s.mfaRepo.GetUnusedRecoveryCode(ctx, userID, hash)
	if err != nil {
		return errorx.ErrMfaCodeInvalid
	}
	return s.mfaRepo.MarkRecoveryCodeUsed(ctx, rc.ID)
}

func (s *MfaService) decryptTOTPSecret(cipherText string) (string, error) {
	if s == nil || s.cfg == nil {
		return "", fmt.Errorf("mfa svc: configuration is nil")
	}

	secret, err := security.DecryptSecret(cipherText, s.cfg.Security.MasterKey)
	if err != nil {
		return "", fmt.Errorf("mfa svc: decrypt totp secret: %w", err)
	}

	return secret, nil
}
