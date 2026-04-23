package entity

import (
	"encoding/json"
	"time"
)

// AuditLog stores security/activity events.
type AuditLog struct {
	ID        string
	UserID    string
	Action    string
	RiskLevel int16
	IPAddress string
	UserAgent string
	DeviceID  string
	Metadata  *json.RawMessage
	CreatedAt time.Time
}
