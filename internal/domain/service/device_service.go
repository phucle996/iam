package domainsvc

import (
	"context"
	"time"

	"controlplane/internal/domain/entity"
)

// DeviceService defines all business-logic contracts for device management.
// AuthService calls Core methods; handlers call Self-service and Admin methods.
type DeviceService interface {
	// ── Core (called by AuthService) ─────────────────────────────────────────

	// ResolveDevice gets or creates a device by fingerprint, binds its key if needed,
	// and refreshes its activity.
	ResolveDevice(ctx context.Context, userID, fingerprint, publicKey, keyAlgorithm string) (*entity.Device, error)

	// UpdateActivity stamps last_active_at for an already-resolved device.
	UpdateActivity(ctx context.Context, deviceID string) error

	// ── Security ──────────────────────────────────────────────────────────────

	// IssueChallenge creates a short-lived challenge nonce for the device to sign.
	IssueChallenge(ctx context.Context, userID, deviceID string) (*entity.DeviceChallenge, error)

	// VerifyProof validates the device's signed challenge response.
	VerifyProof(ctx context.Context, proof *entity.DeviceProof) error

	// RotateKey replaces the device public key after a successful proof.
	RotateKey(ctx context.Context, userID, deviceID, newPublicKey, newAlgorithm string) error

	// Rebind re-attaches a device to a new key pair, requires prior proof.
	Rebind(ctx context.Context, userID string, proof *entity.DeviceProof) error

	// Revoke revokes a single device owned by userID and kills its tokens.
	Revoke(ctx context.Context, userID, deviceID string) error

	// Quarantine flags a device as suspicious without removing it.
	Quarantine(ctx context.Context, deviceID string) error

	// ── User self-service ─────────────────────────────────────────────────────

	// GetByID returns a device, asserting it belongs to userID.
	GetByID(ctx context.Context, userID, deviceID string) (*entity.Device, error)

	// ListByUserID returns all devices registered for a user.
	ListByUserID(ctx context.Context, userID string) ([]*entity.Device, error)

	// RevokeOne revokes exactly one device belonging to the caller.
	RevokeOne(ctx context.Context, userID, deviceID string) error

	// RevokeOthers revokes all devices for userID except keepDeviceID.
	RevokeOthers(ctx context.Context, userID, keepDeviceID string) (int64, error)

	// ── Admin / internal ──────────────────────────────────────────────────────

	// AdminGetByID returns any device by ID (no ownership check).
	AdminGetByID(ctx context.Context, deviceID string) (*entity.Device, error)

	// AdminRevoke force-revokes any device regardless of owner.
	AdminRevoke(ctx context.Context, deviceID string) error

	// MarkSuspicious sets or clears the suspicious flag.
	MarkSuspicious(ctx context.Context, deviceID string, flag bool) error

	// CleanupStale removes devices inactive before the given threshold.
	CleanupStale(ctx context.Context, before time.Time) (int64, error)
}
