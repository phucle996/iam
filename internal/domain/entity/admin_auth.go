package entity

import "time"

const (
	AdminMFAStatusActive   = "active"
	AdminMFAStatusDisabled = "disabled"

	AdminMFATypeTOTP     = "totp"
	AdminMFATypeRecovery = "recovery"

	AdminDeviceStatusActive     = "active"
	AdminDeviceStatusInactive   = "inactive"
	AdminDeviceStatusSuspicious = "suspicious"

	AdminSessionStatusActive     = "active"
	AdminSessionStatusRevoked    = "revoked"
	AdminSessionStatusExpired    = "expired"
	AdminSessionStatusSuspicious = "suspicious"
)

type AdminUser struct {
	ID          string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type AdminAPICredential struct {
	ID                 string
	AdminUserID        string
	TokenHash          string
	ExpiresAt          time.Time
	LastUsedAt         *time.Time
	Suspicious         bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type AdminMFAMethod struct {
	ID              string
	AdminUserID     string
	Method          string
	Status          string
	SecretEncrypted string
	CodeHash        string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type AdminDevice struct {
	ID               string
	AdminUserID      string
	CredentialID     string
	DeviceSecretHash string
	Status           string
	TrustedUntil     *time.Time
	LastSeenAt       time.Time
	LastSeenIP       string
	UserAgent        string
	Suspicious       bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type AdminSession struct {
	ID               string
	AdminUserID      string
	CredentialID     string
	DeviceID         string
	SessionTokenHash string
	Status           string
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type AdminLoginInput struct {
	AdminKey      string
	TwoFactorCode string
	TrustDevice   bool
	ClientIP      string
	UserAgent     string
	DeviceID      string
	DeviceSecret  string
}

type AdminLoginResult struct {
	Admin            *AdminUser
	SessionID        string
	SessionToken     string
	SessionExpiresAt time.Time
	DeviceID         string
	DeviceSecret     string
	DeviceExpiresAt  time.Time
}

type AdminSessionAuthInput struct {
	SessionToken string
	DeviceID     string
	DeviceSecret string
	ClientIP     string
	UserAgent    string
}

type AdminSessionContext struct {
	AdminUserID  string
	DisplayName  string
	CredentialID string
	DeviceID     string
	SessionID    string
	ExpiresAt    time.Time
}

type AdminBootstrapResult struct {
	AdminKey      string
	TOTPSecret    string
	RecoveryCodes []string
	Created       bool
}
