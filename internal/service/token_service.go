package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"iam/internal/config"
	"iam/internal/domain/entity"
	domainrepo "iam/internal/domain/repository"
	"iam/internal/security"
	"iam/pkg/errorx"
	"iam/pkg/id"

	"github.com/redis/go-redis/v9"
)

const (
	// refreshProofWindow is the max age of a signed refresh proof we accept.
	// Prevents replay attacks with stale signatures.
	refreshProofWindow = 5 * time.Minute
	// cleanupBatchSize keeps each expired-token delete query bounded.
	cleanupBatchSize = int64(500)
	// cleanupMaxBatches caps work per worker tick to keep latency stable.
	cleanupMaxBatches = int64(20)
)

// TokenService implements domainsvc.TokenService.
type TokenService struct {
	tokenRepo  domainrepo.TokenRepository
	deviceRepo domainrepo.DeviceRepository
	userRepo   domainrepo.UserRepository
	rdb        *redis.Client
	cfg        *config.Config
	secrets    security.SecretProvider
}

func NewTokenService(
	tokenRepo domainrepo.TokenRepository,
	deviceRepo domainrepo.DeviceRepository,
	userRepo domainrepo.UserRepository,
	rdb *redis.Client,
	cfg *config.Config,
	secrets security.SecretProvider,
) *TokenService {
	return &TokenService{
		tokenRepo:  tokenRepo,
		deviceRepo: deviceRepo,
		userRepo:   userRepo,
		rdb:        rdb,
		cfg:        cfg,
		secrets:    secrets,
	}
}

// ── Flow 1: IssueAfterLogin ───────────────────────────────────────────────────

// IssueAfterLogin generates a refresh token + access token for a newly
// authenticated user/device pair. Called exclusively by AuthService.Login.
func (s *TokenService) IssueAfterLogin(ctx context.Context,
	user *entity.User, device *entity.Device) (*entity.TokenResult, error) {

	if user == nil || device == nil {
		return nil, errorx.ErrTokenGeneration
	}

	now := time.Now().UTC()
	accessExpiresAt := now.Add(s.cfg.Security.AccessSecretTTL)
	refreshExpiresAt := now.Add(s.cfg.Security.RefreshTokenTTL)

	refreshRaw, err := s.issueRefreshToken(ctx, user, device, now)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.issueAccessToken(user, device.ID, now)
	if err != nil {
		return nil, err
	}

	return &entity.TokenResult{
		AccessToken:           accessToken,
		RefreshToken:          refreshRaw,
		DeviceID:              device.ID,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}, nil
}

// IssueForMFA loads user+device from DB then issues a full token pair.
// Called by MfaHandler after MFA verification completes.
func (s *TokenService) IssueForMFA(ctx context.Context, userID, deviceID string) (*entity.TokenResult, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("token svc: get user for mfa: %w", err)
	}

	device, err := s.deviceRepo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("token svc: get device for mfa: %w", err)
	}

	return s.IssueAfterLogin(ctx, user, device)
}

// ── Flow 2: Rotate (client-signed proof) ─────────────────────────────────────

// Rotate validates the client's signed proof, revokes the presented refresh
// token, and issues a brand-new token pair.
//
// Security guarantees:
//  1. Token must exist, be non-revoked, non-expired in DB.
//  2. device_id inside the stored token must match req.DeviceID.
//  3. Client must produce a valid Ed25519/ECDSA signature over the canonical
//     payload using the device private key — server verifies with stored pubkey.
//  4. Proof timestamp must be within refreshProofWindow (replay protection).
//  5. Old token is revoked atomically before new tokens are issued.
func (s *TokenService) Rotate(ctx context.Context, req *entity.RotateToken) (*entity.TokenResult, error) {
	if req == nil {
		return nil, errorx.ErrRefreshTokenInvalid
	}

	rawToken := strings.TrimSpace(req.RawRefreshToken)
	deviceID := strings.TrimSpace(req.DeviceID)
	jti := strings.TrimSpace(req.JTI)
	tokenHash := strings.TrimSpace(req.TokenHash)
	htu := strings.TrimSpace(req.HTU)
	htm := strings.ToUpper(strings.TrimSpace(req.HTM))
	if rawToken == "" || deviceID == "" || jti == "" || tokenHash == "" || htm == "" || htu == "" || req.IssuedAt <= 0 {
		return nil, errorx.ErrRefreshTokenInvalid
	}

	// 1. Hash raw token with active+previous candidates and look up in DB.
	stored, err := s.lookupRefreshTokenByRaw(ctx, rawToken)
	if err != nil {
		if errors.Is(err, errorx.ErrRefreshTokenInvalid) {
			return nil, errorx.ErrRefreshTokenInvalid
		}
		return nil, fmt.Errorf("token svc: lookup: %w", err)
	}

	// 2. Assert device ownership.
	if stored.DeviceID != deviceID {
		return nil, errorx.ErrRefreshTokenMismatch
	}

	// 3. Load device to get stored public key + algorithm.
	device, err := s.deviceRepo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("token svc: get device: %w", err)
	}
	if strings.TrimSpace(device.DevicePublicKey) == "" {
		return nil, errorx.ErrRefreshDeviceUnbound
	}

	now := time.Now().UTC()
	if strings.TrimSpace(req.Signature) == "" {
		return nil, errorx.ErrRefreshSignatureInvalid
	}

	if !strings.EqualFold(htm, "POST") {
		return nil, errorx.ErrRefreshSignatureInvalid
	}

	expectedHTU := buildAbsoluteLink(s.cfg.App.PublicURL, "/api/v1/auth/refresh", nil)
	if htu != expectedHTU {
		return nil, errorx.ErrRefreshSignatureInvalid
	}

	expectedTokenHash := security.HashRefreshToken(rawToken)
	if tokenHash != expectedTokenHash {
		return nil, errorx.ErrRefreshTokenInvalid
	}

	// 4. Timestamp freshness check (replay protection for signed requests).
	reqTime := time.Unix(req.IssuedAt, 0).UTC()
	diff := now.Sub(reqTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > refreshProofWindow {
		return nil, errorx.ErrRefreshSignatureExpired
	}

	// 5. Reconstruct canonical payload and verify signature.
	payload := security.CanonicalRefreshPayload(jti, req.IssuedAt, htm, htu, tokenHash, deviceID)
	if err := security.VerifyDeviceSignature(
		device.DevicePublicKey,
		device.KeyAlgorithm,
		payload,
		req.Signature,
	); err != nil {
		return nil, errorx.ErrRefreshSignatureInvalid
	}

	if err := s.reserveRefreshProof(ctx, deviceID, jti); err != nil {
		return nil, err
	}

	// 6. Load user for access token claims.
	user, err := s.userRepo.GetByID(ctx, stored.UserID)
	if err != nil {
		return nil, fmt.Errorf("token svc: get user: %w", err)
	}

	// 7. Consume the presented token with CAS semantics to prevent double-rotate race.
	consumed, err := s.tokenRepo.ConsumeActive(ctx, stored.ID)
	if err != nil {
		return nil, fmt.Errorf("token svc: consume old token: %w", err)
	}
	if !consumed {
		return nil, errorx.ErrRefreshTokenInvalid
	}

	// 8. Stamp device activity.
	device.LastActiveAt = now
	_ = s.deviceRepo.UpdateDevice(ctx, device) // best-effort

	// 9. Issue new token pair.
	refreshRaw, err := s.issueRefreshToken(ctx, user, device, now)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.issueAccessToken(user, device.ID, now)
	if err != nil {
		return nil, err
	}

	return &entity.TokenResult{
		AccessToken:           accessToken,
		RefreshToken:          refreshRaw,
		DeviceID:              device.ID,
		AccessTokenExpiresAt:  now.Add(s.cfg.Security.AccessSecretTTL),
		RefreshTokenExpiresAt: now.Add(s.cfg.Security.RefreshTokenTTL),
	}, nil
}

// ── private helpers ───────────────────────────────────────────────────────────

func (s *TokenService) issueRefreshToken(ctx context.Context, user *entity.User, device *entity.Device, now time.Time) (string, error) {

	activeSecret, err := s.secrets.GetActive(security.SecretFamilyRefresh)
	if err != nil {
		return "", errorx.ErrTokenGeneration
	}

	rawToken, err := security.GenerateToken(64, activeSecret.Value)
	if err != nil {
		return "", fmt.Errorf("%w: generate: %v", errorx.ErrTokenGeneration, err)
	}

	hash, err := security.HashToken(rawToken, activeSecret.Value)
	if err != nil {
		return "", fmt.Errorf("%w: hash: %v", errorx.ErrTokenGeneration, err)
	}

	tokenID, err := id.Generate()
	if err != nil {
		return "", fmt.Errorf("%w: id: %v", errorx.ErrTokenGeneration, err)
	}

	rt := &entity.RefreshToken{
		ID:        tokenID,
		DeviceID:  device.ID,
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(s.cfg.Security.RefreshTokenTTL),
		IsRevoked: false,
		CreatedAt: now,
	}

	if err := s.tokenRepo.Create(ctx, rt); err != nil {
		return "", err
	}

	return rawToken, nil
}

func (s *TokenService) issueAccessToken(user *entity.User, deviceID string, now time.Time) (string, error) {
	activeSecret, err := s.secrets.GetActive(security.SecretFamilyAccess)
	if err != nil {
		return "", errorx.ErrTokenGeneration
	}

	tokenID, err := id.Generate()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errorx.ErrTokenGeneration, err)
	}

	token, err := security.Sign(security.Claims{
		Subject:   user.ID,
		Role:      user.Role,
		Level:     int(user.SecurityLevel),
		Status:    user.Status,
		DeviceID:  strings.TrimSpace(deviceID),
		TokenID:   tokenID,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(s.cfg.Security.AccessSecretTTL).Unix(),
	}, activeSecret.Value)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errorx.ErrTokenGeneration, err)
	}

	return token, nil
}

func (s *TokenService) lookupRefreshTokenByRaw(ctx context.Context, rawToken string) (*entity.RefreshToken, error) {
	if s == nil || s.secrets == nil {
		return nil, errorx.ErrRefreshTokenInvalid
	}

	candidates, err := s.secrets.GetCandidates(security.SecretFamilyRefresh)
	if err != nil {
		return nil, errorx.ErrRefreshTokenInvalid
	}
	if len(candidates) == 0 {
		return nil, errorx.ErrRefreshTokenInvalid
	}

	for _, candidate := range candidates {
		hash, err := security.HashToken(rawToken, candidate.Value)
		if err != nil {
			continue
		}
		stored, err := s.tokenRepo.GetByHash(ctx, hash)
		if err != nil {
			if errors.Is(err, errorx.ErrRefreshTokenInvalid) {
				continue
			}
			return nil, err
		}
		return stored, nil
	}

	return nil, errorx.ErrRefreshTokenInvalid
}

// RevokeByRaw hashes the token and deletes it.
func (s *TokenService) RevokeByRaw(ctx context.Context, rawRefreshToken string) error {
	stored, err := s.lookupRefreshTokenByRaw(ctx, rawRefreshToken)
	if err != nil {
		return nil
	}
	return s.tokenRepo.Revoke(ctx, stored.ID)
}

// RevokeAllByUser revokes every refresh token for a user.
func (s *TokenService) RevokeAllByUser(ctx context.Context, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errorx.ErrRefreshTokenInvalid
	}
	if s == nil || s.tokenRepo == nil {
		return errorx.ErrRefreshTokenInvalid
	}

	if err := s.tokenRepo.RevokeAllByUser(ctx, userID); err != nil {
		return fmt.Errorf("token svc: revoke all by user: %w", err)
	}

	return nil
}

// CleanupExpired removes expired refresh tokens from storage.
func (s *TokenService) CleanupExpired(ctx context.Context) (int64, error) {
	if s == nil || s.tokenRepo == nil {
		return 0, nil
	}

	var totalDeleted int64
	for i := int64(0); i < cleanupMaxBatches; i++ {
		deleted, err := s.tokenRepo.DeleteExpiredBatch(ctx, cleanupBatchSize)
		if err != nil {
			return totalDeleted, fmt.Errorf("token svc: cleanup expired: %w", err)
		}
		totalDeleted += deleted
		if deleted < cleanupBatchSize {
			break
		}
	}

	return totalDeleted, nil
}

func (s *TokenService) reserveRefreshProof(ctx context.Context, deviceID, jti string) error {
	if s == nil || s.rdb == nil {
		return errorx.ErrRefreshSignatureInvalid
	}

	key := fmt.Sprintf("iam:refresh:proof:%s:%s", strings.TrimSpace(deviceID), strings.TrimSpace(jti))
	ok, err := s.rdb.SetNX(ctx, key, "1", refreshProofWindow).Result()
	if err != nil {
		return fmt.Errorf("token svc: reserve refresh proof: %w", err)
	}
	if !ok {
		return errorx.ErrRefreshSignatureReplay
	}

	return nil
}
