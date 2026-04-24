package model

import (
	"encoding/json"
	"time"

	"iam/internal/domain/entity"
)

// AuditLog mirrors audit_logs.
type AuditLog struct {
	ID        string           `db:"id"`
	UserID    *string          `db:"user_id"`
	Action    string           `db:"action"`
	RiskLevel int16            `db:"risk_level"`
	IPAddress *string          `db:"ip_address"`
	UserAgent *string          `db:"user_agent"`
	DeviceID  *string          `db:"device_id"`
	Metadata  *json.RawMessage `db:"metadata"`
	CreatedAt time.Time        `db:"created_at"`
}

func AuditLogEntityToModel(v *entity.AuditLog) *AuditLog {
	if v == nil {
		return nil
	}
	return &AuditLog{
		ID:        v.ID,
		UserID:    &v.UserID,
		Action:    v.Action,
		RiskLevel: v.RiskLevel,
		IPAddress: &v.IPAddress,
		UserAgent: &v.UserAgent,
		DeviceID:  &v.DeviceID,
		Metadata:  v.Metadata,
		CreatedAt: v.CreatedAt,
	}
}

func AuditLogModelToEntity(v *AuditLog) *entity.AuditLog {
	if v == nil {
		return nil
	}
	return &entity.AuditLog{
		ID:        v.ID,
		UserID:    *v.UserID,
		Action:    v.Action,
		RiskLevel: v.RiskLevel,
		IPAddress: *v.IPAddress,
		UserAgent: *v.UserAgent,
		DeviceID:  *v.DeviceID,
		Metadata:  v.Metadata,
		CreatedAt: v.CreatedAt,
	}
}
