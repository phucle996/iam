package model

import (
	"time"

	"iam/internal/domain/entity"
)

type AdminUser struct {
	ID          string    `db:"id"`
	DisplayName string    `db:"display_name"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

type AdminAPICredential struct {
	ID           string     `db:"id"`
	AdminUserID  string     `db:"admin_user_id"`
	TokenHash    string     `db:"token_hash"`
	ExpiresAt    time.Time  `db:"expires_at"`
	LastUsedAt   *time.Time `db:"last_used_at"`
	Suspicious   bool       `db:"is_suspicious"`
	CreatedAt    time.Time  `db:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at"`
}

type AdminMFAMethod struct {
	ID              string    `db:"id"`
	AdminUserID     string    `db:"admin_user_id"`
	Method          string    `db:"method"`
	Status          string    `db:"status"`
	SecretEncrypted string    `db:"secret_encrypted"`
	CodeHash        string    `db:"code_hash"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

type AdminDevice struct {
	ID               string     `db:"id"`
	AdminUserID      string     `db:"admin_user_id"`
	CredentialID     string     `db:"credential_id"`
	DeviceSecretHash string     `db:"device_secret_hash"`
	Status           string     `db:"status"`
	TrustedUntil     *time.Time `db:"trusted_until"`
	LastSeenAt       time.Time  `db:"last_seen_at"`
	LastSeenIP       string     `db:"last_seen_ip"`
	UserAgent        string     `db:"user_agent"`
	Suspicious       bool       `db:"is_suspicious"`
	CreatedAt        time.Time  `db:"created_at"`
	UpdatedAt        time.Time  `db:"updated_at"`
}

type AdminSession struct {
	ID               string     `db:"id"`
	AdminUserID      string     `db:"admin_user_id"`
	CredentialID     string     `db:"credential_id"`
	DeviceID         string     `db:"device_id"`
	SessionTokenHash string     `db:"session_token_hash"`
	Status           string     `db:"status"`
	ExpiresAt        time.Time  `db:"expires_at"`
	RevokedAt        *time.Time `db:"revoked_at"`
	CreatedAt        time.Time  `db:"created_at"`
	UpdatedAt        time.Time  `db:"updated_at"`
}

func AdminUserEntityToModel(v *entity.AdminUser) *AdminUser {
	if v == nil {
		return nil
	}
	return &AdminUser{
		ID:          v.ID,
		DisplayName: v.DisplayName,
		CreatedAt:   v.CreatedAt,
		UpdatedAt:   v.UpdatedAt,
	}
}

func AdminUserModelToEntity(v *AdminUser) *entity.AdminUser {
	if v == nil {
		return nil
	}
	return &entity.AdminUser{
		ID:          v.ID,
		DisplayName: v.DisplayName,
		CreatedAt:   v.CreatedAt,
		UpdatedAt:   v.UpdatedAt,
	}
}

func AdminAPICredentialEntityToModel(v *entity.AdminAPICredential) *AdminAPICredential {
	if v == nil {
		return nil
	}
	return &AdminAPICredential{
		ID:           v.ID,
		AdminUserID:  v.AdminUserID,
		TokenHash:    v.TokenHash,
		ExpiresAt:    v.ExpiresAt,
		LastUsedAt:   v.LastUsedAt,
		Suspicious:   v.Suspicious,
		CreatedAt:    v.CreatedAt,
		UpdatedAt:    v.UpdatedAt,
	}
}

func AdminAPICredentialModelToEntity(v *AdminAPICredential) *entity.AdminAPICredential {
	if v == nil {
		return nil
	}
	return &entity.AdminAPICredential{
		ID:           v.ID,
		AdminUserID:  v.AdminUserID,
		TokenHash:    v.TokenHash,
		ExpiresAt:    v.ExpiresAt,
		LastUsedAt:   v.LastUsedAt,
		Suspicious:   v.Suspicious,
		CreatedAt:    v.CreatedAt,
		UpdatedAt:    v.UpdatedAt,
	}
}

func AdminMFAMethodModelToEntity(v *AdminMFAMethod) *entity.AdminMFAMethod {
	if v == nil {
		return nil
	}
	return &entity.AdminMFAMethod{
		ID:              v.ID,
		AdminUserID:     v.AdminUserID,
		Method:          v.Method,
		Status:          v.Status,
		SecretEncrypted: v.SecretEncrypted,
		CodeHash:        v.CodeHash,
		CreatedAt:       v.CreatedAt,
		UpdatedAt:       v.UpdatedAt,
	}
}

func AdminMFAMethodEntityToModel(v *entity.AdminMFAMethod) *AdminMFAMethod {
	if v == nil {
		return nil
	}
	return &AdminMFAMethod{
		ID:              v.ID,
		AdminUserID:     v.AdminUserID,
		Method:          v.Method,
		Status:          v.Status,
		SecretEncrypted: v.SecretEncrypted,
		CodeHash:        v.CodeHash,
		CreatedAt:       v.CreatedAt,
		UpdatedAt:       v.UpdatedAt,
	}
}

func AdminDeviceEntityToModel(v *entity.AdminDevice) *AdminDevice {
	if v == nil {
		return nil
	}
	return &AdminDevice{
		ID:               v.ID,
		AdminUserID:      v.AdminUserID,
		CredentialID:     v.CredentialID,
		DeviceSecretHash: v.DeviceSecretHash,
		Status:           v.Status,
		TrustedUntil:     v.TrustedUntil,
		LastSeenAt:       v.LastSeenAt,
		LastSeenIP:       v.LastSeenIP,
		UserAgent:        v.UserAgent,
		Suspicious:       v.Suspicious,
		CreatedAt:        v.CreatedAt,
		UpdatedAt:        v.UpdatedAt,
	}
}

func AdminDeviceModelToEntity(v *AdminDevice) *entity.AdminDevice {
	if v == nil {
		return nil
	}
	return &entity.AdminDevice{
		ID:               v.ID,
		AdminUserID:      v.AdminUserID,
		CredentialID:     v.CredentialID,
		DeviceSecretHash: v.DeviceSecretHash,
		Status:           v.Status,
		TrustedUntil:     v.TrustedUntil,
		LastSeenAt:       v.LastSeenAt,
		LastSeenIP:       v.LastSeenIP,
		UserAgent:        v.UserAgent,
		Suspicious:       v.Suspicious,
		CreatedAt:        v.CreatedAt,
		UpdatedAt:        v.UpdatedAt,
	}
}

func AdminSessionEntityToModel(v *entity.AdminSession) *AdminSession {
	if v == nil {
		return nil
	}
	return &AdminSession{
		ID:               v.ID,
		AdminUserID:      v.AdminUserID,
		CredentialID:     v.CredentialID,
		DeviceID:         v.DeviceID,
		SessionTokenHash: v.SessionTokenHash,
		Status:           v.Status,
		ExpiresAt:        v.ExpiresAt,
		RevokedAt:        v.RevokedAt,
		CreatedAt:        v.CreatedAt,
		UpdatedAt:        v.UpdatedAt,
	}
}

func AdminSessionModelToEntity(v *AdminSession) *entity.AdminSession {
	if v == nil {
		return nil
	}
	return &entity.AdminSession{
		ID:               v.ID,
		AdminUserID:      v.AdminUserID,
		CredentialID:     v.CredentialID,
		DeviceID:         v.DeviceID,
		SessionTokenHash: v.SessionTokenHash,
		Status:           v.Status,
		ExpiresAt:        v.ExpiresAt,
		RevokedAt:        v.RevokedAt,
		CreatedAt:        v.CreatedAt,
		UpdatedAt:        v.UpdatedAt,
	}
}
