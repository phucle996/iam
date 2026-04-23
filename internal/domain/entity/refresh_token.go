package entity

import "time"

// RefreshToken stores a revocable refresh token bound to a device.
type RefreshToken struct {
	ID        string
	DeviceID  string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	IsRevoked bool
	CreatedAt time.Time
}

// RotateToken carries all data needed to perform a token rotation.
type RotateToken struct {
	// RawRefreshToken is the opaque token received at login.
	RawRefreshToken string
	// DeviceID identifies the device making the request.
	DeviceID string
	// JTI is the proof identifier used for replay detection.
	JTI string
	// IssuedAt is the Unix epoch seconds at which the client signed.
	IssuedAt int64
	// HTM is the HTTP method that was signed.
	HTM string
	// HTU is the absolute refresh endpoint URL that was signed.
	HTU string
	// TokenHash is the SHA-256 hash of the refresh cookie exposed to JS.
	TokenHash string
	// Signature is the base64-raw-url encoded signature over the canonical payload.
	Signature string
}

// TokenResult is the response from a successful token issuance or rotation.
type TokenResult struct {
	AccessToken           string
	RefreshToken          string
	DeviceID              string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}
