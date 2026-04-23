package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"controlplane/internal/domain/entity"
	domainrepo "controlplane/internal/domain/repository"
	"controlplane/internal/security"
	"controlplane/pkg/errorx"
	"controlplane/pkg/id"
)

const challengeTTL = 5 * time.Minute

// DeviceService implements iam_domainsvc.DeviceService.
type DeviceService struct {
	repo domainrepo.DeviceRepository
}

func NewDeviceService(repo domainrepo.DeviceRepository) *DeviceService {
	return &DeviceService{repo: repo}
}

// ── Core ─────────────────────────────────────────────────────────────────────

// ResolveDevice gets or creates a device by fingerprint, binding the device key
// only when the existing row has no public key yet.
func (s *DeviceService) ResolveDevice(ctx context.Context, userID, fingerprint, publicKey, keyAlgorithm string) (*entity.Device, error) {
	userID = strings.TrimSpace(userID)
	fingerprint = strings.TrimSpace(fingerprint)
	publicKey = strings.TrimSpace(publicKey)
	keyAlgorithm = strings.TrimSpace(keyAlgorithm)
	if userID == "" || fingerprint == "" || publicKey == "" {
		return nil, errorx.ErrDeviceBindingRequired
	}

	normalizedAlg, err := security.ValidateDevicePublicKey(publicKey, keyAlgorithm)
	if err != nil {
		return nil, errorx.ErrDeviceKeyInvalid
	}

	existing, err := s.repo.GetDeviceByFingerprint(ctx, userID, fingerprint)
	if err != nil && !errors.Is(err, errorx.ErrDeviceNotFound) {
		return nil, err
	}

	now := time.Now().UTC()

	if existing == nil {
		return s.createDevice(ctx, userID, fingerprint, publicKey, normalizedAlg, now)
	}

	return s.refreshDevice(ctx, existing, fingerprint, publicKey, normalizedAlg, now)
}

// UpdateActivity stamps last_active_at for a device that is already resolved.
func (s *DeviceService) UpdateActivity(ctx context.Context, deviceID string) error {
	if deviceID == "" {
		return errorx.ErrDeviceNotFound
	}

	device, err := s.repo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}

	device.LastActiveAt = time.Now().UTC()
	return s.repo.UpdateDevice(ctx, device)
}

// ── Security ──────────────────────────────────────────────────────────────────

// IssueChallenge creates a short-lived nonce for the device to sign.
func (s *DeviceService) IssueChallenge(ctx context.Context, userID, deviceID string) (*entity.DeviceChallenge, error) {
	device, err := s.repo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if device.UserID != userID {
		return nil, errorx.ErrDeviceForbidden
	}

	challengeID, err := id.Generate()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errorx.ErrTokenGeneration, err)
	}

	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errorx.ErrTokenGeneration, err)
	}

	now := time.Now().UTC()
	ch := &entity.DeviceChallenge{
		ChallengeID: challengeID,
		DeviceID:    deviceID,
		UserID:      userID,
		Nonce:       nonce,
		ExpiresAt:   now.Add(challengeTTL),
		CreatedAt:   now,
	}

	if err := s.repo.SaveChallenge(ctx, ch); err != nil {
		return nil, err
	}

	return ch, nil
}

// VerifyProof validates the device's signed challenge response against the
// enrolled device public key.
func (s *DeviceService) VerifyProof(ctx context.Context, proof *entity.DeviceProof) error {
	if s == nil || s.repo == nil || proof == nil {
		return errorx.ErrDeviceProofInvalid
	}

	ch, err := s.repo.GetChallenge(ctx, proof.ChallengeID)
	if err != nil {
		if errors.Is(err, errorx.ErrDeviceChallengeNotFound) {
			return errorx.ErrDeviceChallengeInvalid
		}
		return err
	}

	if ch.DeviceID != proof.DeviceID {
		return errorx.ErrDeviceChallengeInvalid
	}
	if time.Now().UTC().After(ch.ExpiresAt) {
		_ = s.repo.DeleteChallenge(ctx, ch.ChallengeID)
		return errorx.ErrDeviceChallengeInvalid
	}

	device, err := s.repo.GetDeviceByID(ctx, ch.DeviceID)
	if err != nil {
		return err
	}

	if err := security.VerifyDeviceSignature(device.DevicePublicKey, device.KeyAlgorithm, ch.Nonce, proof.Signature); err != nil {
		_ = s.repo.DeleteChallenge(ctx, ch.ChallengeID)
		return errorx.ErrDeviceProofInvalid
	}

	_ = s.repo.DeleteChallenge(ctx, ch.ChallengeID)
	return nil
}

// RotateKey replaces the device public key after a verified proof.
func (s *DeviceService) RotateKey(ctx context.Context, userID, deviceID, newPublicKey, newAlgorithm string) error {
	userID = strings.TrimSpace(userID)
	deviceID = strings.TrimSpace(deviceID)
	newPublicKey = strings.TrimSpace(newPublicKey)
	newAlgorithm = strings.TrimSpace(newAlgorithm)
	if userID == "" || deviceID == "" || newPublicKey == "" {
		return errorx.ErrDeviceKeyInvalid
	}

	normalizedAlg, err := security.ValidateDevicePublicKey(newPublicKey, newAlgorithm)
	if err != nil {
		return errorx.ErrDeviceKeyInvalid
	}

	device, err := s.repo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}
	if device.UserID != userID {
		return errorx.ErrDeviceForbidden
	}

	if err := s.repo.RotateDeviceKey(ctx, deviceID, newPublicKey, normalizedAlg); err != nil {
		return fmt.Errorf("%w: %v", errorx.ErrDeviceKeyRotateFailed, err)
	}

	return nil
}

// Rebind re-attaches a device to a new key pair.
func (s *DeviceService) Rebind(ctx context.Context, userID string, proof *entity.DeviceProof) error {
	if err := s.VerifyProof(ctx, proof); err != nil {
		return err
	}
	return s.RotateKey(ctx, userID, proof.DeviceID, proof.NewPublicKey, proof.NewAlgorithm)
}

// Revoke removes a device owned by userID and kills its tokens.
func (s *DeviceService) Revoke(ctx context.Context, userID, deviceID string) error {
	device, err := s.repo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}
	if device.UserID != userID {
		return errorx.ErrDeviceForbidden
	}

	_ = s.repo.RevokeAllTokensByDevice(ctx, deviceID)
	return s.repo.DeleteDevice(ctx, deviceID)
}

// Quarantine flags a device as suspicious without removing it.
func (s *DeviceService) Quarantine(ctx context.Context, deviceID string) error {
	if deviceID == "" {
		return errorx.ErrDeviceNotFound
	}
	return s.repo.SetSuspicious(ctx, deviceID, true)
}

// ── User self-service ─────────────────────────────────────────────────────────

// GetByID returns a device, asserting it belongs to userID.
func (s *DeviceService) GetByID(ctx context.Context, userID, deviceID string) (*entity.Device, error) {
	if deviceID == "" {
		return nil, errorx.ErrDeviceNotFound
	}

	device, err := s.repo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if device.UserID != userID {
		return nil, errorx.ErrDeviceForbidden
	}

	return device, nil
}

// ListByUserID returns all devices registered for a user.
func (s *DeviceService) ListByUserID(ctx context.Context, userID string) ([]*entity.Device, error) {
	if userID == "" {
		return nil, errorx.ErrDeviceNotFound
	}
	return s.repo.ListDevicesByUserID(ctx, userID)
}

// RevokeOne revokes exactly one device belonging to the caller.
func (s *DeviceService) RevokeOne(ctx context.Context, userID, deviceID string) error {
	return s.Revoke(ctx, userID, deviceID)
}

// RevokeOthers revokes all devices for userID except keepDeviceID.
func (s *DeviceService) RevokeOthers(ctx context.Context, userID, keepDeviceID string) (int64, error) {
	if userID == "" || keepDeviceID == "" {
		return 0, errorx.ErrDeviceNotFound
	}
	return s.repo.RevokeOtherDevices(ctx, userID, keepDeviceID)
}

// ── Admin / internal ──────────────────────────────────────────────────────────

// AdminGetByID returns any device by ID without ownership check.
func (s *DeviceService) AdminGetByID(ctx context.Context, deviceID string) (*entity.Device, error) {
	if deviceID == "" {
		return nil, errorx.ErrDeviceNotFound
	}
	return s.repo.GetDeviceByID(ctx, deviceID)
}

// AdminRevoke force-revokes any device regardless of owner.
func (s *DeviceService) AdminRevoke(ctx context.Context, deviceID string) error {
	if deviceID == "" {
		return errorx.ErrDeviceNotFound
	}
	_ = s.repo.RevokeAllTokensByDevice(ctx, deviceID)
	return s.repo.DeleteDevice(ctx, deviceID)
}

// MarkSuspicious sets or clears the suspicious flag.
func (s *DeviceService) MarkSuspicious(ctx context.Context, deviceID string, flag bool) error {
	if deviceID == "" {
		return errorx.ErrDeviceNotFound
	}
	return s.repo.SetSuspicious(ctx, deviceID, flag)
}

// CleanupStale removes devices inactive before the given threshold.
func (s *DeviceService) CleanupStale(ctx context.Context, before time.Time) (int64, error) {
	return s.repo.CleanupStaleDevices(ctx, before)
}

// ── private helpers ───────────────────────────────────────────────────────────

func (s *DeviceService) createDevice(ctx context.Context, userID, fingerprint, publicKey, keyAlgorithm string, now time.Time) (*entity.Device, error) {
	deviceID, err := id.Generate()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errorx.ErrTokenGeneration, err)
	}

	device := &entity.Device{
		ID:              deviceID,
		UserID:          userID,
		Fingerprint:     fingerprint,
		DevicePublicKey: publicKey,
		KeyAlgorithm:    keyAlgorithm,
		LastActiveAt:    now,
		CreatedAt:       now,
	}

	if err := s.repo.CreateDevice(ctx, device); err != nil {
		return nil, err
	}

	return device, nil
}

func (s *DeviceService) refreshDevice(ctx context.Context, device *entity.Device, fingerprint, publicKey, keyAlgorithm string, now time.Time) (*entity.Device, error) {
	if strings.TrimSpace(device.DevicePublicKey) == "" {
		device.DevicePublicKey = publicKey
		device.KeyAlgorithm = keyAlgorithm
	}
	device.Fingerprint = fingerprint
	device.LastActiveAt = now

	if err := s.repo.UpdateDevice(ctx, device); err != nil {
		return nil, err
	}

	return device, nil
}

func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
