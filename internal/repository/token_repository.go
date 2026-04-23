package repository

import (
	"context"
	"controlplane/internal/domain/entity"
	"controlplane/internal/model"
	"controlplane/pkg/errorx"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenRepository persists refresh tokens for session management.
type TokenRepository struct {
	db *pgxpool.Pool
}

func NewTokenRepository(db *pgxpool.Pool) *TokenRepository {
	return &TokenRepository{db: db}
}

// Create inserts a new refresh token record.
func (r *TokenRepository) Create(ctx context.Context, token *entity.RefreshToken) error {
	if r == nil || r.db == nil {
		return errorx.ErrTokenGeneration
	}

	t := model.RefreshTokenEntityToModel(token)
	if t == nil {
		return errorx.ErrTokenGeneration
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO refresh_tokens (
			id, device_id, user_id, token_hash, expires_at, is_revoked, created_at
		) VALUES ($1, $2, $3, $4, $5, false, NOW())`,
		t.ID, t.DeviceID, t.UserID, t.TokenHash, t.ExpiresAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return errorx.ErrTokenGeneration
		}
		return fmt.Errorf("token repo: create: %w", err)
	}

	return nil
}

// GetByHash looks up an active refresh token by its HMAC digest.
func (r *TokenRepository) GetByHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrRefreshTokenInvalid
	}

	var row model.RefreshToken

	err := r.db.QueryRow(ctx, `
		SELECT id, device_id, user_id, token_hash, expires_at, is_revoked, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND is_revoked = false
		  AND expires_at > NOW()`,
		tokenHash,
	).Scan(
		&row.ID, &row.DeviceID, &row.UserID,
		&row.TokenHash, &row.ExpiresAt, &row.IsRevoked, &row.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrRefreshTokenInvalid
		}
		return nil, fmt.Errorf("token repo: get by hash: %w", err)
	}

	return model.RefreshTokenModelToEntity(&row), nil
}

// Revoke marks a single token as revoked.
func (r *TokenRepository) Revoke(ctx context.Context, tokenID string) error {
	if r == nil || r.db == nil {
		return errorx.ErrRefreshTokenInvalid
	}

	tag, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET is_revoked = true WHERE id = $1`,
		tokenID,
	)
	if err != nil {
		return fmt.Errorf("token repo: revoke: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrRefreshTokenInvalid
	}

	return nil
}

// ConsumeActive marks exactly one active token as revoked.
// It returns true only when a row matched:
//   - id = tokenID
//   - is_revoked = false
//   - expires_at > NOW()
func (r *TokenRepository) ConsumeActive(ctx context.Context, tokenID string) (bool, error) {
	if r == nil || r.db == nil {
		return false, nil
	}

	tag, err := r.db.Exec(ctx, `
		UPDATE refresh_tokens
		SET is_revoked = true
		WHERE id = $1
		  AND is_revoked = false
		  AND expires_at > NOW()`,
		tokenID,
	)
	if err != nil {
		return false, fmt.Errorf("token repo: consume active: %w", err)
	}

	return tag.RowsAffected() == 1, nil
}

// RevokeAllByDevice revokes every token bound to a given device.
func (r *TokenRepository) RevokeAllByDevice(ctx context.Context, deviceID string) error {
	if r == nil || r.db == nil {
		return nil
	}

	_, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET is_revoked = true WHERE device_id = $1`,
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("token repo: revoke by device: %w", err)
	}

	return nil
}

// RevokeAllByUser revokes every token for a user (e.g. password change).
func (r *TokenRepository) RevokeAllByUser(ctx context.Context, userID string) error {
	if r == nil || r.db == nil {
		return nil
	}

	_, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET is_revoked = true WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("token repo: revoke by user: %w", err)
	}

	return nil
}

// DeleteExpired hard-deletes expired token rows (admin maintenance).
func (r *TokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}

	tag, err := r.db.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at < $1`,
		time.Now().UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("token repo: delete expired: %w", err)
	}

	return tag.RowsAffected(), nil
}

// DeleteExpiredBatch removes expired rows in bounded chunks to avoid large spikes.
func (r *TokenRepository) DeleteExpiredBatch(ctx context.Context, limit int64) (int64, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	if limit <= 0 {
		return 0, nil
	}

	tag, err := r.db.Exec(ctx, `
		WITH doomed AS (
			SELECT id
			FROM refresh_tokens
			WHERE expires_at < NOW()
			ORDER BY expires_at ASC
			LIMIT $1
		)
		DELETE FROM refresh_tokens t
		USING doomed
		WHERE t.id = doomed.id`,
		limit,
	)
	if err != nil {
		return 0, fmt.Errorf("token repo: delete expired batch: %w", err)
	}

	return tag.RowsAffected(), nil
}
