package domainsvc

import (
	"context"

	"iam/internal/domain/entity"
)

// MfaService encapsulates all MFA business logic.
//
// ── Login Integration ──────────────────────────────────────────────────────────
//
//	AuthService.Login calls CheckAndChallenge after successful password verification.
//	If the user has any enabled MFA method, a challenge is stored in Redis (3 min TTL)
//	and LoginResult{MFARequired: true, MFAChallengeID: ..., MFAAvailableMethods: ...}
//	is returned instead of tokens.
//
//	The client then calls POST /api/v1/mfa/verify with the challenge ID + code.
//	On success, full token pair is issued and returned.
//
// ── Self-service ───────────────────────────────────────────────────────────────
//
//	Users can enroll TOTP, enable/disable/delete methods, set primary method,
//	and regenerate recovery codes (all require a valid access token).
type MfaService interface {
	// ── Login integration ──────────────────────────────────────────────────────

	// CheckAndChallenge checks whether the user has active MFA methods.
	// If yes, creates a Redis challenge and returns (true, challengeID, methods, nil).
	// If no MFA is configured, returns (false, "", nil, nil).
	CheckAndChallenge(ctx context.Context, userID, deviceID string) (required bool, challengeID string, methods []string, err error)

	// Verify validates the code presented by the client against the active challenge.
	// On success it consumes the challenge and returns the user+device IDs so the caller
	// (AuthService) can issue the token pair.
	//
	// method must be one of entity.MfaType* constants.
	// If method == entity.MfaTypeRecovery, code is a recovery code (not an OTP).
	Verify(ctx context.Context, challengeID, method, code string) (userID, deviceID string, err error)

	// ── Enrollment ─────────────────────────────────────────────────────────────

	// EnrollTOTP generates a new TOTP secret, stores it (pending confirmation),
	// and returns the provisioning URI for QR generation.
	EnrollTOTP(ctx context.Context, userID, deviceName string) (settingID string, provisioningURI string, err error)

	// ConfirmTOTP verifies the first TOTP code and marks the enrollment as active.
	ConfirmTOTP(ctx context.Context, userID, settingID, code string) error

	// ── Management ─────────────────────────────────────────────────────────────

	// ListMethods returns all enabled MFA methods for the authenticated user.
	ListMethods(ctx context.Context, userID string) ([]*entity.MfaSetting, error)

	// EnableMethod re-enables a previously disabled method.
	EnableMethod(ctx context.Context, userID, settingID string) error

	// DisableMethod disables (but does not delete) a method.
	DisableMethod(ctx context.Context, userID, settingID string) error

	// DeleteMethod unenrolls a method entirely.
	DeleteMethod(ctx context.Context, userID, settingID string) error

	// ── Recovery ───────────────────────────────────────────────────────────────

	// GenerateRecoveryCodes creates a fresh set of 10 backup codes and returns
	// the plaintext codes (shown once; hashes stored in DB).
	GenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error)
}
