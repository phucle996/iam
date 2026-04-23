package repository

import (
	"context"
	"controlplane/internal/domain/entity"
	"controlplane/internal/model"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
			WHERE expires_at > NOW()
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
		INSERT INTO admin_api_tokens (id, token_hash, is_bootstrap, expires_at, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, dbToken.ID, dbToken.TokenHash, dbToken.IsBootstrap, dbToken.ExpiresAt); err != nil {
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
			  AND expires_at > NOW()
		)
	`, tokenHash).Scan(&exists); err != nil {
		return false, fmt.Errorf("iam repo: exists admin api token hash: %w", err)
	}

	return exists, nil
}

func (r *AdminAPITokenRepository) GetActiveByHash(ctx context.Context, tokenHash string) (*entity.AdminAPIToken, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("iam repo: admin api token db is nil")
	}

	var dbToken model.AdminAPIToken
	err := r.db.QueryRow(ctx, `
		SELECT id, token_hash, created_at, expires_at, is_bootstrap
		FROM admin_api_tokens
		WHERE token_hash = $1
		  AND expires_at > NOW()
		LIMIT 1
	`, tokenHash).Scan(
		&dbToken.ID,
		&dbToken.TokenHash,
		&dbToken.CreatedAt,
		&dbToken.ExpiresAt,
		&dbToken.IsBootstrap,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("iam repo: get active admin api token by hash: %w", err)
	}

	return model.AdminAPITokenModelToEntity(&dbToken), nil
}

func (r *AdminAPITokenRepository) RotateToken(ctx context.Context, id, oldHash, newHash string, expiresAt time.Time, isBootstrap bool) (bool, error) {
	if r == nil || r.db == nil {
		return false, fmt.Errorf("iam repo: admin api token db is nil")
	}

	result, err := r.db.Exec(ctx, `
		UPDATE admin_api_tokens
		SET token_hash = $1,
		    is_bootstrap = $2,
		    expires_at = $3,
		    created_at = NOW()
		WHERE id = $4
		  AND token_hash = $5
		  AND expires_at > NOW()
	`, newHash, isBootstrap, expiresAt, id, oldHash)
	if err != nil {
		return false, fmt.Errorf("iam repo: rotate admin api token: %w", err)
	}

	return result.RowsAffected() == 1, nil
}

func (r *AdminAPITokenRepository) PurgeExpired(ctx context.Context, limit int64) (int64, error) {
	if r == nil || r.db == nil {
		return 0, fmt.Errorf("iam repo: admin api token db is nil")
	}
	if limit <= 0 {
		limit = 500
	}

	result, err := r.db.Exec(ctx, `
		DELETE FROM admin_api_tokens
		WHERE id IN (
			SELECT id
			FROM admin_api_tokens
			WHERE expires_at <= NOW()
			ORDER BY expires_at ASC
			LIMIT $1
		)
	`, limit)
	if err != nil {
		return 0, fmt.Errorf("iam repo: purge expired admin api tokens: %w", err)
	}

	return result.RowsAffected(), nil
}
