package domainrepo

import (
	"context"
	"time"

	"controlplane/internal/domain/entity"
)

// DeviceRepository defines all data-access methods for Device management.
type DeviceRepository interface {
	// ── Core ──────────────────────────────────────────────────────────────────
	GetDeviceByFingerprint(ctx context.Context, userID, fingerprint string) (*entity.Device, error)
	GetDeviceByID(ctx context.Context, deviceID string) (*entity.Device, error)
	CreateDevice(ctx context.Context, device *entity.Device) error
	UpdateDevice(ctx context.Context, device *entity.Device) error
	CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error

	// ── User self-service ─────────────────────────────────────────────────────
	ListDevicesByUserID(ctx context.Context, userID string) ([]*entity.Device, error)
	DeleteDevice(ctx context.Context, deviceID string) error
	RevokeOtherDevices(ctx context.Context, userID, keepDeviceID string) (int64, error)

	// ── Security ──────────────────────────────────────────────────────────────
	SaveChallenge(ctx context.Context, ch *entity.DeviceChallenge) error
	GetChallenge(ctx context.Context, challengeID string) (*entity.DeviceChallenge, error)
	DeleteChallenge(ctx context.Context, challengeID string) error
	RotateDeviceKey(ctx context.Context, deviceID, newPublicKey, newAlgorithm string) error
	RevokeAllTokensByDevice(ctx context.Context, deviceID string) error

	// ── Admin ─────────────────────────────────────────────────────────────────
	SetSuspicious(ctx context.Context, deviceID string, suspicious bool) error
	CleanupStaleDevices(ctx context.Context, before time.Time) (int64, error)
}
