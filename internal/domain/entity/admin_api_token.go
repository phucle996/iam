package entity

import "time"

// AdminAPIToken represents a hashed admin API token stored in IAM schema.
type AdminAPIToken struct {
	ID          string
	TokenHash   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	IsBootstrap bool
}

type AdminAPIAuthorization struct {
	Valid       bool
	CookieToken string
	ExpiresAt   time.Time
}
