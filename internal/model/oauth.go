package model

import (
	"iam/internal/domain/entity"
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
	AllowedScopes    json.RawMessage `db:"allowed_scopes"`
	IsActive         bool            `db:"is_active"`
	SecretRotatedAt  *time.Time      `db:"secret_rotated_at"`
	Metadata         json.RawMessage `db:"metadata"`
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
		AllowedScopes:    v.AllowedScopes,
		IsActive:         v.IsActive,
		SecretRotatedAt:  v.SecretRotatedAt,
		Metadata:         v.Metadata,
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
		AllowedScopes:    v.AllowedScopes,
		IsActive:         v.IsActive,
		SecretRotatedAt:  v.SecretRotatedAt,
		Metadata:         v.Metadata,
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

// OAuthAuthorizationCode mirrors oauth_authorization_codes.
type OAuthAuthorizationCode struct {
	ID                  string           `db:"id"`
	CodeHash            string           `db:"code_hash"`
	UserID              string           `db:"user_id"`
	ClientID            string           `db:"client_id"`
	RedirectURI         string           `db:"redirect_uri"`
	Scopes              *json.RawMessage `db:"scopes"`
	CodeChallenge       string           `db:"code_challenge"`
	CodeChallengeMethod string           `db:"code_challenge_method"`
	ExpiresAt           time.Time        `db:"expires_at"`
	ConsumedAt          *time.Time       `db:"consumed_at"`
	CreatedAt           time.Time        `db:"created_at"`
}

func OAuthAuthorizationCodeEntityToModel(v *entity.OAuthAuthorizationCode) *OAuthAuthorizationCode {
	if v == nil {
		return nil
	}
	return &OAuthAuthorizationCode{
		ID:                  v.ID,
		CodeHash:            v.CodeHash,
		UserID:              v.UserID,
		ClientID:            v.ClientID,
		RedirectURI:         v.RedirectURI,
		Scopes:              v.Scopes,
		CodeChallenge:       v.CodeChallenge,
		CodeChallengeMethod: v.CodeChallengeMethod,
		ExpiresAt:           v.ExpiresAt,
		ConsumedAt:          v.ConsumedAt,
		CreatedAt:           v.CreatedAt,
	}
}

func OAuthAuthorizationCodeModelToEntity(v *OAuthAuthorizationCode) *entity.OAuthAuthorizationCode {
	if v == nil {
		return nil
	}
	return &entity.OAuthAuthorizationCode{
		ID:                  v.ID,
		CodeHash:            v.CodeHash,
		UserID:              v.UserID,
		ClientID:            v.ClientID,
		RedirectURI:         v.RedirectURI,
		Scopes:              v.Scopes,
		CodeChallenge:       v.CodeChallenge,
		CodeChallengeMethod: v.CodeChallengeMethod,
		ExpiresAt:           v.ExpiresAt,
		ConsumedAt:          v.ConsumedAt,
		CreatedAt:           v.CreatedAt,
	}
}

// OAuthRefreshToken mirrors oauth_refresh_tokens.
type OAuthRefreshToken struct {
	ID            string           `db:"id"`
	TokenHash     string           `db:"token_hash"`
	ClientID      string           `db:"client_id"`
	UserID        *string          `db:"user_id"`
	Scopes        *json.RawMessage `db:"scopes"`
	ExpiresAt     time.Time        `db:"expires_at"`
	RevokedAt     *time.Time       `db:"revoked_at"`
	RotatedFromID *string          `db:"rotated_from_id"`
	ReplacedByID  *string          `db:"replaced_by_id"`
	CreatedAt     time.Time        `db:"created_at"`
	UpdatedAt     time.Time        `db:"updated_at"`
}

func OAuthRefreshTokenEntityToModel(v *entity.OAuthRefreshToken) *OAuthRefreshToken {
	if v == nil {
		return nil
	}
	return &OAuthRefreshToken{
		ID:            v.ID,
		TokenHash:     v.TokenHash,
		ClientID:      v.ClientID,
		UserID:        v.UserID,
		Scopes:        v.Scopes,
		ExpiresAt:     v.ExpiresAt,
		RevokedAt:     v.RevokedAt,
		RotatedFromID: v.RotatedFromID,
		ReplacedByID:  v.ReplacedByID,
		CreatedAt:     v.CreatedAt,
		UpdatedAt:     v.UpdatedAt,
	}
}

func OAuthRefreshTokenModelToEntity(v *OAuthRefreshToken) *entity.OAuthRefreshToken {
	if v == nil {
		return nil
	}
	return &entity.OAuthRefreshToken{
		ID:            v.ID,
		TokenHash:     v.TokenHash,
		ClientID:      v.ClientID,
		UserID:        v.UserID,
		Scopes:        v.Scopes,
		ExpiresAt:     v.ExpiresAt,
		RevokedAt:     v.RevokedAt,
		RotatedFromID: v.RotatedFromID,
		ReplacedByID:  v.ReplacedByID,
		CreatedAt:     v.CreatedAt,
		UpdatedAt:     v.UpdatedAt,
	}
}
