package domainsvc

import (
	"context"

	"controlplane/internal/domain/entity"
)

// TokenResult is the response from a successful token issuance or rotation.

// TokenService encapsulates all refresh-token lifecycle business logic.
//
// Flow 1 — IssueAfterLogin:
//
//	Called by AuthService after successful credential verification.
//	Returns a signed opaque refresh token + HMAC-SHA256 access token (JWT).
//
// Flow 1b — IssueForMFA:
//
//	Called by MfaHandler after successful MFA verification.
//	Loads user+device from DB then delegates to IssueAfterLogin.
//
// Flow 2 — Rotate (client-signed proof):
//
//	Client sends an Ed25519/ECDSA signature over the canonical signing payload
//	together with the refresh-token and device-id cookies.
//	Server verifies the signature against the device's stored public key,
//	then rotates: old token revoked → new refresh + new access token issued.
type TokenService interface {
	// IssueAfterLogin creates a refresh token + access token for a newly
	// authenticated user/device pair. Called exclusively by AuthService.Login.
	IssueAfterLogin(ctx context.Context, user *entity.User, device *entity.Device) (*entity.TokenResult, error)

	// IssueForMFA loads user+device by IDs and issues a full token pair.
	// Called by MfaHandler after the MFA challenge is successfully verified.
	IssueForMFA(ctx context.Context, userID, deviceID string) (*entity.TokenResult, error)

	// Rotate verifies the client-provided signed proof, revokes the presented
	// refresh token, and issues a fresh token pair.
	Rotate(ctx context.Context, req *entity.RotateToken) (*entity.TokenResult, error)

	// RevokeByRaw hashes the raw refresh token and revokes it in the repository.
	// Used primarily for Logout.
	RevokeByRaw(ctx context.Context, rawRefreshToken string) error

	// RevokeAllByUser revokes every refresh token issued to a user.
	// Used after password reset to force re-authentication everywhere.
	RevokeAllByUser(ctx context.Context, userID string) error

	// CleanupExpired removes expired refresh tokens from storage.
	CleanupExpired(ctx context.Context) (int64, error)
}
