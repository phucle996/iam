package model

import (
	"time"

	"iam/internal/domain/entity"
)

// MfaSetting mirrors mfa_settings.
type MfaSetting struct {
	ID              string    `db:"id"`
	UserID          string    `db:"user_id"`
	MfaType         string    `db:"mfa_type"`
	DeviceName      *string   `db:"device_name"`
	IsPrimary       bool      `db:"is_primary"`
	SecretEncrypted string    `db:"secret_encrypted"`
	IsEnabled       bool      `db:"is_enabled"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

func MfaSettingEntityToModel(v *entity.MfaSetting) *MfaSetting {
	if v == nil {
		return nil
	}
	return &MfaSetting{
		ID:              v.ID,
		UserID:          v.UserID,
		MfaType:         v.MfaType,
		DeviceName:      &v.DeviceName,
		IsPrimary:       v.IsPrimary,
		SecretEncrypted: v.SecretEncrypted,
		IsEnabled:       v.IsEnabled,
		CreatedAt:       v.CreatedAt,
		UpdatedAt:       v.UpdatedAt,
	}
}

func MfaSettingModelToEntity(v *MfaSetting) *entity.MfaSetting {
	if v == nil {
		return nil
	}
	return &entity.MfaSetting{
		ID:              v.ID,
		UserID:          v.UserID,
		MfaType:         v.MfaType,
		DeviceName:      *v.DeviceName,
		IsPrimary:       v.IsPrimary,
		SecretEncrypted: v.SecretEncrypted,
		IsEnabled:       v.IsEnabled,
		CreatedAt:       v.CreatedAt,
		UpdatedAt:       v.UpdatedAt,
	}
}

// RecoveryCode mirrors recovery_codes.
type RecoveryCode struct {
	ID        string     `db:"id"`
	UserID    string     `db:"user_id"`
	CodeHash  string     `db:"code_hash"`
	IsUsed    bool       `db:"is_used"`
	UsedAt    *time.Time `db:"used_at"`
	CreatedAt time.Time  `db:"created_at"`
}

func RecoveryCodeEntityToModel(v *entity.RecoveryCode) *RecoveryCode {
	if v == nil {
		return nil
	}
	return &RecoveryCode{
		ID:        v.ID,
		UserID:    v.UserID,
		CodeHash:  v.CodeHash,
		IsUsed:    v.IsUsed,
		UsedAt:    v.UsedAt,
		CreatedAt: v.CreatedAt,
	}
}

func RecoveryCodeModelToEntity(v *RecoveryCode) *entity.RecoveryCode {
	if v == nil {
		return nil
	}
	return &entity.RecoveryCode{
		ID:        v.ID,
		UserID:    v.UserID,
		CodeHash:  v.CodeHash,
		IsUsed:    v.IsUsed,
		UsedAt:    v.UsedAt,
		CreatedAt: v.CreatedAt,
	}
}
