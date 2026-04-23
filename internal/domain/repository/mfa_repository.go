package domainrepo

import (
	"context"

	"controlplane/internal/domain/entity"
)

// MfaRepository handles persistence for MFA settings and recovery codes.
// Redis challenge state is managed in MfaService directly (not here).
type MfaRepository interface {
	// ── Settings ──────────────────────────────────────────────────────────────

	// ListEnabled returns all enabled MFA methods for a user.
	ListEnabled(ctx context.Context, userID string) ([]*entity.MfaSetting, error)

	// GetByID fetches a single MFA setting.
	GetByID(ctx context.Context, id string) (*entity.MfaSetting, error)

	// GetByUserAndType returns the (single) enabled setting for a user + MFA type.
	GetByUserAndType(ctx context.Context, userID, mfaType string) (*entity.MfaSetting, error)

	// Create persists a new MFA method (e.g. enrolled TOTP).
	Create(ctx context.Context, setting *entity.MfaSetting) error

	// UpdateEnabled flips is_enabled on a setting.
	UpdateEnabled(ctx context.Context, id string, enabled bool) error

	// SetPrimary marks one method as primary, clearing all others for the user.
	SetPrimary(ctx context.Context, userID, settingID string) error

	// Delete removes a setting (unenrollment).
	Delete(ctx context.Context, id, userID string) error

	// ── Recovery Codes ────────────────────────────────────────────────────────

	// ReplaceRecoveryCodes replaces all existing codes for a user with new ones.
	ReplaceRecoveryCodes(ctx context.Context, codes []*entity.RecoveryCode) error

	// GetUnusedRecoveryCode looks for a recovery code matching the given hash.
	GetUnusedRecoveryCode(ctx context.Context, userID, codeHash string) (*entity.RecoveryCode, error)

	// MarkRecoveryCodeUsed marks a code as consumed.
	MarkRecoveryCodeUsed(ctx context.Context, id string) error
}
