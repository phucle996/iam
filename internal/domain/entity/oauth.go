package entity

import (
	"encoding/json"
	"time"
)

// OAuthClient represents a registered OAuth/SSO client.
type OAuthClient struct {
	ID               string
	ClientID         string
	ClientSecretHash string
	Name             string
	RedirectURIs     json.RawMessage
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// OAuthGrant stores consent grants for OAuth clients.
type OAuthGrant struct {
	ID        string
	UserID    string
	ClientID  string
	Scopes    *json.RawMessage
	CreatedAt time.Time
}
