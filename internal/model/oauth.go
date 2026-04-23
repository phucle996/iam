package model

import (
	"controlplane/internal/domain/entity"
	"encoding/json"
	"time"
)

// OAuthClient mirrors oauth_clients.
type OAuthClient struct {
	ID               string          `db:"id"`
	ClientID         string          `db:"client_id"`
	ClientSecretHash string          `db:"client_secret_hash"`
	Name             string          `db:"name"`
	RedirectURIs     json.RawMessage `db:"redirect_uris"`
	CreatedAt        time.Time       `db:"created_at"`
	UpdatedAt        time.Time       `db:"updated_at"`
}

func OAuthClientEntityToModel(v *entity.OAuthClient) *OAuthClient {
	if v == nil {
		return nil
	}
	return &OAuthClient{
		ID:               v.ID,
		ClientID:         v.ClientID,
		ClientSecretHash: v.ClientSecretHash,
		Name:             v.Name,
		RedirectURIs:     v.RedirectURIs,
		CreatedAt:        v.CreatedAt,
		UpdatedAt:        v.UpdatedAt,
	}
}

func OAuthClientModelToEntity(v *OAuthClient) *entity.OAuthClient {
	if v == nil {
		return nil
	}
	return &entity.OAuthClient{
		ID:               v.ID,
		ClientID:         v.ClientID,
		ClientSecretHash: v.ClientSecretHash,
		Name:             v.Name,
		RedirectURIs:     v.RedirectURIs,
		CreatedAt:        v.CreatedAt,
		UpdatedAt:        v.UpdatedAt,
	}
}

// OAuthGrant mirrors oauth_grants.
type OAuthGrant struct {
	ID        string           `db:"id"`
	UserID    string           `db:"user_id"`
	ClientID  string           `db:"client_id"`
	Scopes    *json.RawMessage `db:"scopes"`
	CreatedAt time.Time        `db:"created_at"`
}

func OAuthGrantEntityToModel(v *entity.OAuthGrant) *OAuthGrant {
	if v == nil {
		return nil
	}
	return &OAuthGrant{
		ID:        v.ID,
		UserID:    v.UserID,
		ClientID:  v.ClientID,
		Scopes:    v.Scopes,
		CreatedAt: v.CreatedAt,
	}
}

func OAuthGrantModelToEntity(v *OAuthGrant) *entity.OAuthGrant {
	if v == nil {
		return nil
	}
	return &entity.OAuthGrant{
		ID:        v.ID,
		UserID:    v.UserID,
		ClientID:  v.ClientID,
		Scopes:    v.Scopes,
		CreatedAt: v.CreatedAt,
	}
}
