package entity

import "time"

// Device represents a trusted or registered user device.
type Device struct {
	ID              string
	UserID          string
	DevicePublicKey string
	KeyAlgorithm    string
	Fingerprint     string
	DeviceName      string
	LastIP          string
	LastActiveAt    time.Time
	IsSuspicious    bool
	RevokedAt       *time.Time
	CreatedAt       time.Time
}

// DeviceChallenge is a short-lived nonce issued to a device to prove possession.
type DeviceChallenge struct {
	ChallengeID string
	DeviceID    string
	UserID      string
	Nonce       string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// DeviceProof carries the device's signed response to a challenge.
type DeviceProof struct {
	ChallengeID  string
	DeviceID     string
	Signature    string
	NewPublicKey string
	NewAlgorithm string
}

// WebauthnCredential stores passkey / WebAuthn credentials.
type WebauthnCredential struct {
	ID           string
	UserID       string
	CredentialID string
	PublicKey    string
	SignCount    int64
	DeviceName   string
	CreatedAt    time.Time
}
