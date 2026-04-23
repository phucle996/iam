package model

import (
	"controlplane/internal/domain/entity"
	"time"
)

// AdminAPIToken is a row in admin_api_tokens.
type AdminAPIToken struct {
	ID          string    `db:"id"`
	TokenHash   string    `db:"token_hash"`
	CreatedAt   time.Time `db:"created_at"`
	ExpiresAt   time.Time `db:"expires_at"`
	IsBootstrap bool      `db:"is_bootstrap"`
}

func AdminAPITokenEntityToModel(v *entity.AdminAPIToken) *AdminAPIToken {
	if v == nil {
		return nil
	}

	return &AdminAPIToken{
		ID:          v.ID,
		TokenHash:   v.TokenHash,
		CreatedAt:   v.CreatedAt,
		ExpiresAt:   v.ExpiresAt,
		IsBootstrap: v.IsBootstrap,
	}
}

func AdminAPITokenModelToEntity(v *AdminAPIToken) *entity.AdminAPIToken {
	if v == nil {
		return nil
	}

	return &entity.AdminAPIToken{
		ID:          v.ID,
		TokenHash:   v.TokenHash,
		CreatedAt:   v.CreatedAt,
		ExpiresAt:   v.ExpiresAt,
		IsBootstrap: v.IsBootstrap,
	}
}
