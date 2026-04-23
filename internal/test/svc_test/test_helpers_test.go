package svc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	"controlplane/internal/domain/entity"
	"controlplane/internal/security"
	"controlplane/pkg/errorx"
)

type fakeSecretProvider struct {
	active     security.SecretVersion
	candidates []security.SecretVersion
}

func (f *fakeSecretProvider) GetActive(family string) (security.SecretVersion, error) {
	return f.active, nil
}

func (f *fakeSecretProvider) GetCandidates(family string) ([]security.SecretVersion, error) {
	if len(f.candidates) > 0 {
		return f.candidates, nil
	}
	if f.active.Value == "" {
		return nil, security.ErrSecretUnavailable
	}
	return []security.SecretVersion{f.active}, nil
}

type stubUserRepo struct {
	usersByID       map[string]*entity.User
	usersByEmail    map[string]*entity.User
	usersByUsername map[string]*entity.User
	profilesByUser  map[string]*entity.UserProfile
	whoAmiByUserID  map[string]*entity.WhoAmI
	whoAmiCalls     int

	updatedUserID       string
	updatedPasswordHash string
	updatePasswordErr   error
}

func (r *stubUserRepo) CreatePendingAccount(ctx context.Context, user *entity.User, profile *entity.UserProfile) error {
	return nil
}

func (r *stubUserRepo) Activate(ctx context.Context, userID string) error {
	return nil
}

func (r *stubUserRepo) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	if r != nil && r.usersByEmail != nil {
		if user, ok := r.usersByEmail[email]; ok {
			return cloneUser(user), nil
		}
	}
	return nil, errorx.ErrUserNotFound
}

func (r *stubUserRepo) GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	if r != nil && r.usersByUsername != nil {
		if user, ok := r.usersByUsername[username]; ok {
			return cloneUser(user), nil
		}
	}
	return nil, errorx.ErrUserNotFound
}

func (r *stubUserRepo) GetByID(ctx context.Context, id string) (*entity.User, error) {
	if r != nil && r.usersByID != nil {
		if user, ok := r.usersByID[id]; ok {
			return cloneUser(user), nil
		}
	}
	return nil, errorx.ErrUserNotFound
}

func (r *stubUserRepo) GetProfileByUserID(ctx context.Context, userID string) (*entity.UserProfile, error) {
	if r != nil && r.profilesByUser != nil {
		if profile, ok := r.profilesByUser[userID]; ok {
			return cloneProfile(profile), nil
		}
	}
	return nil, errorx.ErrProfileNotFound
}

func (r *stubUserRepo) GetWhoAmI(ctx context.Context, userID string) (*entity.WhoAmI, error) {
	if r != nil {
		r.whoAmiCalls++
	}
	if r != nil && r.whoAmiByUserID != nil {
		if snapshot, ok := r.whoAmiByUserID[userID]; ok {
			return cloneWhoAmI(snapshot), nil
		}
	}
	return nil, errorx.ErrUserNotFound
}

func (r *stubUserRepo) UpdatePassword(ctx context.Context, userID, newPasswordHash string) error {
	if r != nil {
		r.updatedUserID = userID
		r.updatedPasswordHash = newPasswordHash
		if r.updatePasswordErr != nil {
			return r.updatePasswordErr
		}
	}
	return nil
}

func (r *stubUserRepo) CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	return nil
}

type stubMfaRepo struct {
	mfa *entity.MfaSetting
}

func (r *stubMfaRepo) ListEnabled(ctx context.Context, userID string) ([]*entity.MfaSetting, error) {
	if r != nil && r.mfa != nil && r.mfa.UserID == userID && r.mfa.IsEnabled {
		return []*entity.MfaSetting{cloneMfaSetting(r.mfa)}, nil
	}
	return nil, nil
}

func (r *stubMfaRepo) GetByID(ctx context.Context, id string) (*entity.MfaSetting, error) {
	if r != nil && r.mfa != nil && r.mfa.ID == id {
		return cloneMfaSetting(r.mfa), nil
	}
	return nil, errorx.ErrMfaSettingNotFound
}

func (r *stubMfaRepo) GetByUserAndType(ctx context.Context, userID, mfaType string) (*entity.MfaSetting, error) {
	if r != nil && r.mfa != nil && r.mfa.UserID == userID && r.mfa.MfaType == mfaType && r.mfa.IsEnabled {
		return cloneMfaSetting(r.mfa), nil
	}
	return nil, errorx.ErrMfaSettingNotFound
}

func (r *stubMfaRepo) Create(ctx context.Context, setting *entity.MfaSetting) error {
	if r != nil {
		r.mfa = cloneMfaSetting(setting)
	}
	return nil
}

func (r *stubMfaRepo) UpdateEnabled(ctx context.Context, id string, enabled bool) error {
	if r != nil && r.mfa != nil && r.mfa.ID == id {
		r.mfa.IsEnabled = enabled
		return nil
	}
	return errorx.ErrMfaSettingNotFound
}

func (r *stubMfaRepo) SetPrimary(ctx context.Context, userID, settingID string) error {
	return nil
}

func (r *stubMfaRepo) Delete(ctx context.Context, id, userID string) error {
	return nil
}

func (r *stubMfaRepo) ReplaceRecoveryCodes(ctx context.Context, codes []*entity.RecoveryCode) error {
	return nil
}

func (r *stubMfaRepo) GetUnusedRecoveryCode(ctx context.Context, userID, codeHash string) (*entity.RecoveryCode, error) {
	return nil, errorx.ErrMfaCodeInvalid
}

func (r *stubMfaRepo) MarkRecoveryCodeUsed(ctx context.Context, id string) error {
	return nil
}

type stubDeviceRepo struct {
	device               *entity.Device
	challenge            *entity.DeviceChallenge
	rotatedPublicKey     string
	rotatedAlgorithm     string
	revokeTokensByDevice string
}

func (r *stubDeviceRepo) GetDeviceByFingerprint(ctx context.Context, userID, fingerprint string) (*entity.Device, error) {
	if r != nil && r.device != nil && r.device.UserID == userID && r.device.Fingerprint == fingerprint {
		return cloneDevice(r.device), nil
	}
	return nil, errorx.ErrDeviceNotFound
}

func (r *stubDeviceRepo) GetDeviceByID(ctx context.Context, deviceID string) (*entity.Device, error) {
	if r != nil && r.device != nil && r.device.ID == deviceID {
		return cloneDevice(r.device), nil
	}
	return nil, errorx.ErrDeviceNotFound
}

func (r *stubDeviceRepo) CreateDevice(ctx context.Context, device *entity.Device) error {
	if r != nil {
		r.device = cloneDevice(device)
	}
	return nil
}

func (r *stubDeviceRepo) UpdateDevice(ctx context.Context, device *entity.Device) error {
	if r != nil {
		r.device = cloneDevice(device)
	}
	return nil
}

func (r *stubDeviceRepo) CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	return nil
}

func (r *stubDeviceRepo) ListDevicesByUserID(ctx context.Context, userID string) ([]*entity.Device, error) {
	return nil, nil
}

func (r *stubDeviceRepo) DeleteDevice(ctx context.Context, deviceID string) error {
	return nil
}

func (r *stubDeviceRepo) RevokeOtherDevices(ctx context.Context, userID, keepDeviceID string) (int64, error) {
	return 0, nil
}

func (r *stubDeviceRepo) SaveChallenge(ctx context.Context, ch *entity.DeviceChallenge) error {
	if r != nil {
		r.challenge = cloneChallenge(ch)
	}
	return nil
}

func (r *stubDeviceRepo) GetChallenge(ctx context.Context, challengeID string) (*entity.DeviceChallenge, error) {
	if r != nil && r.challenge != nil && r.challenge.ChallengeID == challengeID {
		return cloneChallenge(r.challenge), nil
	}
	return nil, errorx.ErrDeviceChallengeNotFound
}

func (r *stubDeviceRepo) DeleteChallenge(ctx context.Context, challengeID string) error {
	if r != nil && r.challenge != nil && r.challenge.ChallengeID == challengeID {
		r.challenge = nil
	}
	return nil
}

func (r *stubDeviceRepo) RotateDeviceKey(ctx context.Context, deviceID, newPublicKey, newAlgorithm string) error {
	if r != nil && r.device != nil && r.device.ID == deviceID {
		r.device.DevicePublicKey = newPublicKey
		r.device.KeyAlgorithm = newAlgorithm
		r.rotatedPublicKey = newPublicKey
		r.rotatedAlgorithm = newAlgorithm
		return nil
	}
	return errorx.ErrDeviceNotFound
}

func (r *stubDeviceRepo) RevokeAllTokensByDevice(ctx context.Context, deviceID string) error {
	if r != nil {
		r.revokeTokensByDevice = deviceID
	}
	return nil
}

func (r *stubDeviceRepo) SetSuspicious(ctx context.Context, deviceID string, suspicious bool) error {
	return nil
}

func (r *stubDeviceRepo) CleanupStaleDevices(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type stubTokenRepo struct {
	revokedUserID            string
	revokedTokenID           string
	consumeActiveTokenID     string
	consumeActiveOK          bool
	consumeActiveErr         error
	deletedExpired           int64
	deleteExpiredErr         error
	deleteExpiredCalled      bool
	deleteExpiredBatchCalled bool
	deleteExpiredBatchLimit  int64
	deleteExpiredBatchCalls  int
	deleteExpiredBatchSeq    []int64
	tokenByHash              *entity.RefreshToken
}

func (r *stubTokenRepo) Create(ctx context.Context, token *entity.RefreshToken) error {
	return nil
}

func (r *stubTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error) {
	if r != nil && r.tokenByHash != nil {
		return cloneRefreshToken(r.tokenByHash), nil
	}
	return nil, errorx.ErrRefreshTokenInvalid
}

func (r *stubTokenRepo) Revoke(ctx context.Context, tokenID string) error {
	if r != nil {
		r.revokedTokenID = tokenID
	}
	return nil
}

func (r *stubTokenRepo) ConsumeActive(ctx context.Context, tokenID string) (bool, error) {
	if r != nil {
		r.consumeActiveTokenID = tokenID
		if r.consumeActiveErr != nil {
			return false, r.consumeActiveErr
		}
		return r.consumeActiveOK, nil
	}
	return false, nil
}

func (r *stubTokenRepo) RevokeAllByDevice(ctx context.Context, deviceID string) error {
	return nil
}

func (r *stubTokenRepo) RevokeAllByUser(ctx context.Context, userID string) error {
	if r != nil {
		r.revokedUserID = userID
	}
	return nil
}

func (r *stubTokenRepo) DeleteExpired(ctx context.Context) (int64, error) {
	if r != nil {
		r.deleteExpiredCalled = true
		if r.deleteExpiredErr != nil {
			return 0, r.deleteExpiredErr
		}
		return r.deletedExpired, nil
	}
	return 0, nil
}

func (r *stubTokenRepo) DeleteExpiredBatch(ctx context.Context, limit int64) (int64, error) {
	if r != nil {
		r.deleteExpiredBatchCalled = true
		r.deleteExpiredBatchLimit = limit
		r.deleteExpiredBatchCalls++
		if r.deleteExpiredErr != nil {
			return 0, r.deleteExpiredErr
		}
		if len(r.deleteExpiredBatchSeq) > 0 {
			next := r.deleteExpiredBatchSeq[0]
			r.deleteExpiredBatchSeq = r.deleteExpiredBatchSeq[1:]
			return next, nil
		}
		return r.deletedExpired, nil
	}
	return 0, nil
}

type stubTokenService struct {
	issueAfterLoginCalled   bool
	issueAfterLoginUserID   string
	issueAfterLoginDeviceID string
	revokeByRawToken        string
	revokeAllUserID         string
}

func (s *stubTokenService) IssueAfterLogin(ctx context.Context, user *entity.User, device *entity.Device) (*entity.TokenResult, error) {
	if s != nil {
		s.issueAfterLoginCalled = true
		if user != nil {
			s.issueAfterLoginUserID = user.ID
		}
		if device != nil {
			s.issueAfterLoginDeviceID = device.ID
		}
	}
	return &entity.TokenResult{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		DeviceID:     "device-from-token",
	}, nil
}

func (s *stubTokenService) IssueForMFA(ctx context.Context, userID, deviceID string) (*entity.TokenResult, error) {
	return &entity.TokenResult{}, nil
}

func (s *stubTokenService) Rotate(ctx context.Context, req *entity.RotateToken) (*entity.TokenResult, error) {
	return &entity.TokenResult{}, nil
}

func (s *stubTokenService) RevokeByRaw(ctx context.Context, rawRefreshToken string) error {
	if s != nil {
		s.revokeByRawToken = rawRefreshToken
	}
	return nil
}

func (s *stubTokenService) RevokeAllByUser(ctx context.Context, userID string) error {
	if s != nil {
		s.revokeAllUserID = userID
	}
	return nil
}

func (s *stubTokenService) CleanupExpired(ctx context.Context) (int64, error) {
	return 0, nil
}

type stubAdminAPITokenService struct {
	valid bool
	err   error
}

func (s *stubAdminAPITokenService) EnsureBootstrapToken(ctx context.Context) (string, bool, error) {
	return "", false, nil
}

func (s *stubAdminAPITokenService) Validate(ctx context.Context, token string) (bool, error) {
	if s != nil && s.err != nil {
		return false, s.err
	}
	if s == nil {
		return false, nil
	}
	return s.valid, nil
}

func (s *stubAdminAPITokenService) Authorize(ctx context.Context, token string) (*entity.AdminAPIAuthorization, error) {
	ok, err := s.Validate(ctx, token)
	if err != nil {
		return nil, err
	}
	if !ok {
		return &entity.AdminAPIAuthorization{Valid: false}, nil
	}
	return &entity.AdminAPIAuthorization{
		Valid:       true,
		CookieToken: token,
		ExpiresAt:   time.Now().UTC().Add(15 * time.Minute),
	}, nil
}

func (s *stubAdminAPITokenService) PurgeExpired(ctx context.Context, limit int64) (int64, error) {
	return 0, nil
}

func cloneUser(v *entity.User) *entity.User {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func cloneProfile(v *entity.UserProfile) *entity.UserProfile {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func cloneWhoAmI(v *entity.WhoAmI) *entity.WhoAmI {
	if v == nil {
		return nil
	}
	cp := *v
	cp.Roles = append([]string(nil), v.Roles...)
	cp.Permissions = append([]string(nil), v.Permissions...)
	return &cp
}

func cloneMfaSetting(v *entity.MfaSetting) *entity.MfaSetting {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func cloneDevice(v *entity.Device) *entity.Device {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func cloneChallenge(v *entity.DeviceChallenge) *entity.DeviceChallenge {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func cloneRefreshToken(v *entity.RefreshToken) *entity.RefreshToken {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func encodeEd25519PublicKeyPEM(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}))
}

func encodeECDSAP256PublicKeyPEM(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}))
}

func signNonceWithEd25519(priv ed25519.PrivateKey, nonce string) string {
	digest := sha256.Sum256([]byte(nonce))
	sig := ed25519.Sign(priv, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig)
}
