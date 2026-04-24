package repository

import (
	"context"
	"iam/internal/domain/entity"
	"iam/internal/model"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type AdminAPITokenRepository struct {
	db *pgxpool.Pool
}

func NewAdminAPITokenRepository(db *pgxpool.Pool) *AdminAPITokenRepository {
	return &AdminAPITokenRepository{db: db}
}

func (r *AdminAPITokenRepository) HasAdminAPITokens(ctx context.Context) (bool, error) {
	if r == nil || r.db == nil {
		return false, fmt.Errorf("iam repo: admin api token db is nil")
	}

	var exists bool
	if err := r.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM admin_api_tokens
		)
	`).Scan(&exists); err != nil {
		return false, fmt.Errorf("iam repo: has admin api tokens: %w", err)
	}

	return exists, nil
}

func (r *AdminAPITokenRepository) CreateAdminAPIToken(ctx context.Context, token *entity.AdminAPIToken) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin api token db is nil")
	}

	dbToken := model.AdminAPITokenEntityToModel(token)
	if dbToken == nil {
		return fmt.Errorf("iam repo: admin api token model is nil")
	}

	if _, err := r.db.Exec(ctx, `
		INSERT INTO admin_api_tokens (id, token_hash, created_at)
		VALUES ($1, $2, NOW())
	`, dbToken.ID, dbToken.TokenHash); err != nil {
		return fmt.Errorf("iam repo: create admin api token: %w", err)
	}

	return nil
}

func (r *AdminAPITokenRepository) ExistsAdminAPITokenHash(ctx context.Context, tokenHash string) (bool, error) {
	if r == nil || r.db == nil {
		return false, fmt.Errorf("iam repo: admin api token db is nil")
	}

	var exists bool
	if err := r.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM admin_api_tokens
			WHERE token_hash = $1
		)
	`, tokenHash).Scan(&exists); err != nil {
		return false, fmt.Errorf("iam repo: exists admin api token hash: %w", err)
	}

	return exists, nil
}
