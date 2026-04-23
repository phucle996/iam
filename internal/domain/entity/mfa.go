package entity

import "time"

// ── MFA Types ─────────────────────────────────────────────────────────────────

const (
	MfaTypeTOTP     = "totp"
	MfaTypeSMS      = "sms"
	MfaTypeEmail    = "email"
	MfaTypeRecovery = "recovery"
)

// MfaSetting stores a user MFA authenticator enrollment.
type MfaSetting struct {
	ID              string
	UserID          string
	MfaType         string // one of MfaType* constants
	DeviceName      string
	IsPrimary       bool
	SecretEncrypted string // AES-GCM encrypted TOTP secret, blank for SMS/email
	IsEnabled       bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// RecoveryCode stores a backup code for MFA recovery.
type RecoveryCode struct {
	ID        string
	UserID    string
	CodeHash  string
	IsUsed    bool
	UsedAt    *time.Time
	CreatedAt time.Time
}

// MfaChallenge is the in-flight MFA state stored in Redis.
type MfaChallenge struct {
	ChallengeID      string
	UserID           string
	DeviceID         string
	AvailableMethods []string
	SelectedMethod   string
	OTPCode          string
	ExpiresAt        time.Time
	CreatedAt        time.Time
}
