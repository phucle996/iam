package entity

import "time"

// LoginResult represents the outcome of a login attempt.
type LoginResult struct {
	// Token fields — populated only after full authentication (no MFA pending).
	AccessToken           string
	RefreshToken          string
	DeviceID              string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time

	// Pending flow flags.
	Pending     bool // true = account not yet activated
	MFARequired bool // true = MFA challenge issued; client must call /auth/mfa/verify

	// MFA challenge info — populated when MFARequired = true.
	MFAChallengeID      string
	MFAAvailableMethods []string
}

// WhoAmI is the flattened authenticated session view returned by /whoami.
type WhoAmI struct {
	UserID         string
	Username       string
	Email          string
	Phone          string
	FullName       string
	Company        string
	ReferralSource string
	JobFunction    string
	Country        string
	AvatarURL      string
	Bio            string
	Status         string
	OnBoarding     bool
	Roles          []string
	Permissions    []string
}
