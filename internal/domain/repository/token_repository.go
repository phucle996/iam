package domainrepo

import (
	"context"

	"iam/internal/domain/entity"
)

// TokenRepository defines persistence operations for refresh tokens.
// It is intentionally separate from DeviceRepository (device lifecycle)
// and UserRepository (user identity).
type TokenRepository interface {
	// Create persists a new hashed refresh token record.
	Create(ctx context.Context, token *entity.RefreshToken) error

	// GetByHash looks up a non-revoked, non-expired token by its HMAC digest.
	GetByHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error)

	// Revoke marks a single token as revoked (soft-delete; keeps audit trail).
	Revoke(ctx context.Context, tokenID string) error

	// ConsumeActive performs compare-and-swap style consume for one active token.
	// Returns true only when a non-revoked and non-expired token was consumed.
	ConsumeActive(ctx context.Context, tokenID string) (bool, error)

	// RevokeAllByDevice revokes every token bound to a device.
	RevokeAllByDevice(ctx context.Context, deviceID string) error

	// RevokeAllByUser revokes every token belonging to a user (e.g. password change).
	RevokeAllByUser(ctx context.Context, userID string) error

	// DeleteExpired hard-deletes tokens past their expiry (admin cleanup).
	DeleteExpired(ctx context.Context) (int64, error)

	// DeleteExpiredBatch hard-deletes up to "limit" expired rows.
	DeleteExpiredBatch(ctx context.Context, limit int64) (int64, error)
}
