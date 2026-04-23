package model

import (
	"controlplane/internal/domain/entity"
	"time"
)

// Device mirrors devices.
type Device struct {
	ID              string     `db:"id"`
	UserID          string     `db:"user_id"`
	DevicePublicKey string     `db:"device_public_key"`
	KeyAlgorithm    string     `db:"key_algorithm"`
	Fingerprint     string     `db:"fingerprint"`
	DeviceName      *string    `db:"device_name"`
	LastIP          *string    `db:"last_ip"`
	LastActiveAt    time.Time  `db:"last_active_at"`
	IsSuspicious    bool       `db:"is_suspicious"`
	RevokedAt       *time.Time `db:"revoked_at"`
	CreatedAt       time.Time  `db:"created_at"`
}

func DeviceEntityToModel(v *entity.Device) *Device {
	if v == nil {
		return nil
	}

	row := &Device{
		ID:              v.ID,
		UserID:          v.UserID,
		DevicePublicKey: v.DevicePublicKey,
		KeyAlgorithm:    v.KeyAlgorithm,
		Fingerprint:     v.Fingerprint,
		LastActiveAt:    v.LastActiveAt,
		IsSuspicious:    v.IsSuspicious,
		RevokedAt:       v.RevokedAt,
		CreatedAt:       v.CreatedAt,
	}

	if v.DeviceName != "" {
		deviceName := v.DeviceName
		row.DeviceName = &deviceName
	}

	if v.LastIP != "" {
		lastIP := v.LastIP
		row.LastIP = &lastIP
	}

	return row
}

func DeviceModelToEntity(v *Device) *entity.Device {
	if v == nil {
		return nil
	}

	var deviceName, lastIP string
	if v.DeviceName != nil {
		deviceName = *v.DeviceName
	}
	if v.LastIP != nil {
		lastIP = *v.LastIP
	}

	return &entity.Device{
		ID:              v.ID,
		UserID:          v.UserID,
		DevicePublicKey: v.DevicePublicKey,
		KeyAlgorithm:    v.KeyAlgorithm,
		Fingerprint:     v.Fingerprint,
		DeviceName:      deviceName,
		LastIP:          lastIP,
		LastActiveAt:    v.LastActiveAt,
		IsSuspicious:    v.IsSuspicious,
		RevokedAt:       v.RevokedAt,
		CreatedAt:       v.CreatedAt,
	}
}

// RefreshToken mirrors refresh_tokens.
type RefreshToken struct {
	ID        string    `db:"id"`
	DeviceID  string    `db:"device_id"`
	UserID    string    `db:"user_id"`
	TokenHash string    `db:"token_hash"`
	ExpiresAt time.Time `db:"expires_at"`
	IsRevoked bool      `db:"is_revoked"`
	CreatedAt time.Time `db:"created_at"`
}

func RefreshTokenEntityToModel(v *entity.RefreshToken) *RefreshToken {
	if v == nil {
		return nil
	}
	return &RefreshToken{
		ID:        v.ID,
		DeviceID:  v.DeviceID,
		UserID:    v.UserID,
		TokenHash: v.TokenHash,
		ExpiresAt: v.ExpiresAt,
		IsRevoked: v.IsRevoked,
		CreatedAt: v.CreatedAt,
	}
}

func RefreshTokenModelToEntity(v *RefreshToken) *entity.RefreshToken {
	if v == nil {
		return nil
	}
	return &entity.RefreshToken{
		ID:        v.ID,
		DeviceID:  v.DeviceID,
		UserID:    v.UserID,
		TokenHash: v.TokenHash,
		ExpiresAt: v.ExpiresAt,
		IsRevoked: v.IsRevoked,
		CreatedAt: v.CreatedAt,
	}
}

// WebauthnCredential mirrors iam.webauthn_credentials.
type WebauthnCredential struct {
	ID           string    `db:"id"`
	UserID       string    `db:"user_id"`
	CredentialID string    `db:"credential_id"`
	PublicKey    string    `db:"public_key"`
	SignCount    int64     `db:"sign_count"`
	DeviceName   *string   `db:"device_name"`
	CreatedAt    time.Time `db:"created_at"`
}

func WebauthnCredentialEntityToModel(v *entity.WebauthnCredential) *WebauthnCredential {
	if v == nil {
		return nil
	}
	return &WebauthnCredential{
		ID:           v.ID,
		UserID:       v.UserID,
		CredentialID: v.CredentialID,
		PublicKey:    v.PublicKey,
		SignCount:    v.SignCount,
		DeviceName:   &v.DeviceName,
		CreatedAt:    v.CreatedAt,
	}
}

func WebauthnCredentialModelToEntity(v *WebauthnCredential) *entity.WebauthnCredential {
	if v == nil {
		return nil
	}
	return &entity.WebauthnCredential{
		ID:           v.ID,
		UserID:       v.UserID,
		CredentialID: v.CredentialID,
		PublicKey:    v.PublicKey,
		SignCount:    v.SignCount,
		DeviceName:   *v.DeviceName,
		CreatedAt:    v.CreatedAt,
	}
}
