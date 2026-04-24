package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"iam/internal/domain/entity"
	"iam/internal/model"
	"iam/pkg/errorx"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OAuthRepository persists OAuth clients, grants, and token artifacts.
type OAuthRepository struct {
	db *pgxpool.Pool
}

func NewOAuthRepository(db *pgxpool.Pool) *OAuthRepository {
	return &OAuthRepository{db: db}
}

func (r *OAuthRepository) CreateClient(ctx context.Context, client *entity.OAuthClient) error {
	if r == nil || r.db == nil || client == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	m := model.OAuthClientEntityToModel(client)
	if m == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO oauth_clients (
			id, client_id, client_secret_hash, name, redirect_uris,
			allowed_scopes, is_active, secret_rotated_at, metadata, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())`,
		m.ID,
		m.ClientID,
		m.ClientSecretHash,
		m.Name,
		m.RedirectURIs,
		m.AllowedScopes,
		m.IsActive,
		m.SecretRotatedAt,
		m.Metadata,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return errorx.ErrOAuthInvalidClient
		}
		return fmt.Errorf("oauth repo: create client: %w", err)
	}

	return nil
}

func (r *OAuthRepository) ListClients(ctx context.Context, limit, offset int) ([]*entity.OAuthClient, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, client_id, client_secret_hash, name, redirect_uris,
		       allowed_scopes, is_active, secret_rotated_at, metadata,
		       created_at, updated_at
		FROM oauth_clients
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`,
		limit,
		offset,
	)
	if err != nil {
		return nil, fmt.Errorf("oauth repo: list clients: %w", err)
	}
	defer rows.Close()

	result := make([]*entity.OAuthClient, 0, limit)
	for rows.Next() {
		var m model.OAuthClient
		if err := rows.Scan(
			&m.ID,
			&m.ClientID,
			&m.ClientSecretHash,
			&m.Name,
			&m.RedirectURIs,
			&m.AllowedScopes,
			&m.IsActive,
			&m.SecretRotatedAt,
			&m.Metadata,
			&m.CreatedAt,
			&m.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("oauth repo: scan client: %w", err)
		}
		result = append(result, model.OAuthClientModelToEntity(&m))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oauth repo: iterate clients: %w", err)
	}

	return result, nil
}

func (r *OAuthRepository) GetClientByClientID(ctx context.Context, clientID string) (*entity.OAuthClient, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrOAuthClientNotFound
	}

	var m model.OAuthClient
	err := r.db.QueryRow(ctx, `
		SELECT id, client_id, client_secret_hash, name, redirect_uris,
		       allowed_scopes, is_active, secret_rotated_at, metadata,
		       created_at, updated_at
		FROM oauth_clients
		WHERE client_id = $1
		LIMIT 1`,
		clientID,
	).Scan(
		&m.ID,
		&m.ClientID,
		&m.ClientSecretHash,
		&m.Name,
		&m.RedirectURIs,
		&m.AllowedScopes,
		&m.IsActive,
		&m.SecretRotatedAt,
		&m.Metadata,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrOAuthClientNotFound
		}
		return nil, fmt.Errorf("oauth repo: get client by client_id: %w", err)
	}

	return model.OAuthClientModelToEntity(&m), nil
}

func (r *OAuthRepository) GetClientByID(ctx context.Context, id string) (*entity.OAuthClient, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrOAuthClientNotFound
	}

	var m model.OAuthClient
	err := r.db.QueryRow(ctx, `
		SELECT id, client_id, client_secret_hash, name, redirect_uris,
		       allowed_scopes, is_active, secret_rotated_at, metadata,
		       created_at, updated_at
		FROM oauth_clients
		WHERE id = $1
		LIMIT 1`,
		id,
	).Scan(
		&m.ID,
		&m.ClientID,
		&m.ClientSecretHash,
		&m.Name,
		&m.RedirectURIs,
		&m.AllowedScopes,
		&m.IsActive,
		&m.SecretRotatedAt,
		&m.Metadata,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrOAuthClientNotFound
		}
		return nil, fmt.Errorf("oauth repo: get client by id: %w", err)
	}

	return model.OAuthClientModelToEntity(&m), nil
}

func (r *OAuthRepository) UpdateClient(ctx context.Context, client *entity.OAuthClient) error {
	if r == nil || r.db == nil || client == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	m := model.OAuthClientEntityToModel(client)
	if m == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	tag, err := r.db.Exec(ctx, `
		UPDATE oauth_clients
		SET name = $2,
		    redirect_uris = $3,
		    allowed_scopes = $4,
		    is_active = $5,
		    metadata = $6,
		    updated_at = NOW()
		WHERE client_id = $1`,
		m.ClientID,
		m.Name,
		m.RedirectURIs,
		m.AllowedScopes,
		m.IsActive,
		m.Metadata,
	)
	if err != nil {
		return fmt.Errorf("oauth repo: update client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrOAuthClientNotFound
	}

	return nil
}

func (r *OAuthRepository) DeleteClientByClientID(ctx context.Context, clientID string) error {
	if r == nil || r.db == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	tag, err := r.db.Exec(ctx, `DELETE FROM oauth_clients WHERE client_id = $1`, clientID)
	if err != nil {
		return fmt.Errorf("oauth repo: delete client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrOAuthClientNotFound
	}

	return nil
}

func (r *OAuthRepository) RotateClientSecret(ctx context.Context, clientID, secretHash string, rotatedAt time.Time) error {
	if r == nil || r.db == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	tag, err := r.db.Exec(ctx, `
		UPDATE oauth_clients
		SET client_secret_hash = $2,
		    secret_rotated_at = $3,
		    updated_at = NOW()
		WHERE client_id = $1`,
		clientID,
		secretHash,
		rotatedAt,
	)
	if err != nil {
		return fmt.Errorf("oauth repo: rotate client secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrOAuthClientNotFound
	}

	return nil
}

func (r *OAuthRepository) GetGrant(ctx context.Context, userID, clientID string) (*entity.OAuthGrant, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrOAuthGrantNotFound
	}

	var m model.OAuthGrant
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, client_id, scopes, created_at
		FROM oauth_grants
		WHERE user_id = $1 AND client_id = $2
		LIMIT 1`,
		userID,
		clientID,
	).Scan(&m.ID, &m.UserID, &m.ClientID, &m.Scopes, &m.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrOAuthGrantNotFound
		}
		return nil, fmt.Errorf("oauth repo: get grant: %w", err)
	}

	return model.OAuthGrantModelToEntity(&m), nil
}

func (r *OAuthRepository) UpsertGrant(ctx context.Context, grant *entity.OAuthGrant) error {
	if r == nil || r.db == nil || grant == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	m := model.OAuthGrantEntityToModel(grant)
	if m == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO oauth_grants (id, user_id, client_id, scopes, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (user_id, client_id)
		DO UPDATE SET scopes = EXCLUDED.scopes`,
		m.ID,
		m.UserID,
		m.ClientID,
		m.Scopes,
	)
	if err != nil {
		return fmt.Errorf("oauth repo: upsert grant: %w", err)
	}

	return nil
}

func (r *OAuthRepository) ListGrantsByUser(ctx context.Context, userID string) ([]*entity.OAuthGrant, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, client_id, scopes, created_at
		FROM oauth_grants
		WHERE user_id = $1
		ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("oauth repo: list grants by user: %w", err)
	}
	defer rows.Close()

	result := make([]*entity.OAuthGrant, 0)
	for rows.Next() {
		var m model.OAuthGrant
		if err := rows.Scan(&m.ID, &m.UserID, &m.ClientID, &m.Scopes, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("oauth repo: scan grant: %w", err)
		}
		result = append(result, model.OAuthGrantModelToEntity(&m))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oauth repo: iterate grants: %w", err)
	}

	return result, nil
}

func (r *OAuthRepository) RevokeGrant(ctx context.Context, userID, clientID string) error {
	if r == nil || r.db == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	tag, err := r.db.Exec(ctx, `DELETE FROM oauth_grants WHERE user_id = $1 AND client_id = $2`, userID, clientID)
	if err != nil {
		return fmt.Errorf("oauth repo: revoke grant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrOAuthGrantNotFound
	}

	return nil
}

func (r *OAuthRepository) RevokeGrantsByClient(ctx context.Context, clientID string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errorx.ErrOAuthInvalidRequest
	}

	tag, err := r.db.Exec(ctx, `DELETE FROM oauth_grants WHERE client_id = $1`, clientID)
	if err != nil {
		return 0, fmt.Errorf("oauth repo: revoke grants by client: %w", err)
	}

	return tag.RowsAffected(), nil
}

func (r *OAuthRepository) CreateAuthorizationCode(ctx context.Context, code *entity.OAuthAuthorizationCode) error {
	if r == nil || r.db == nil || code == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	m := model.OAuthAuthorizationCodeEntityToModel(code)
	if m == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO oauth_authorization_codes (
			id, code_hash, user_id, client_id, redirect_uri,
			scopes, code_challenge, code_challenge_method,
			expires_at, consumed_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, NOW())`,
		m.ID,
		m.CodeHash,
		m.UserID,
		m.ClientID,
		m.RedirectURI,
		m.Scopes,
		m.CodeChallenge,
		m.CodeChallengeMethod,
		m.ExpiresAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return errorx.ErrOAuthReplayDetected
		}
		return fmt.Errorf("oauth repo: create authorization code: %w", err)
	}

	return nil
}

func (r *OAuthRepository) ConsumeAuthorizationCode(ctx context.Context, codeHash string, consumedAt time.Time) (*entity.OAuthAuthorizationCode, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrOAuthInvalidGrant
	}

	var m model.OAuthAuthorizationCode
	err := r.db.QueryRow(ctx, `
		UPDATE oauth_authorization_codes
		SET consumed_at = $2
		WHERE code_hash = $1
		  AND consumed_at IS NULL
		  AND expires_at > NOW()
		RETURNING id, code_hash, user_id, client_id, redirect_uri,
		          scopes, code_challenge, code_challenge_method,
		          expires_at, consumed_at, created_at`,
		codeHash,
		consumedAt,
	).Scan(
		&m.ID,
		&m.CodeHash,
		&m.UserID,
		&m.ClientID,
		&m.RedirectURI,
		&m.Scopes,
		&m.CodeChallenge,
		&m.CodeChallengeMethod,
		&m.ExpiresAt,
		&m.ConsumedAt,
		&m.CreatedAt,
	)
	if err == nil {
		return model.OAuthAuthorizationCodeModelToEntity(&m), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("oauth repo: consume authorization code: %w", err)
	}

	var expiresAt time.Time
	var consumed *time.Time
	checkErr := r.db.QueryRow(ctx, `
		SELECT expires_at, consumed_at
		FROM oauth_authorization_codes
		WHERE code_hash = $1
		LIMIT 1`, codeHash).Scan(&expiresAt, &consumed)
	if checkErr != nil {
		if errors.Is(checkErr, pgx.ErrNoRows) {
			return nil, errorx.ErrOAuthCodeNotFound
		}
		return nil, fmt.Errorf("oauth repo: check authorization code state: %w", checkErr)
	}

	if consumed != nil {
		return nil, errorx.ErrOAuthCodeConsumed
	}
	if !expiresAt.After(time.Now().UTC()) {
		return nil, errorx.ErrOAuthCodeExpired
	}

	return nil, errorx.ErrOAuthInvalidGrant
}

func (r *OAuthRepository) CreateRefreshToken(ctx context.Context, token *entity.OAuthRefreshToken) error {
	if r == nil || r.db == nil || token == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	m := model.OAuthRefreshTokenEntityToModel(token)
	if m == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (
			id, token_hash, client_id, user_id, scopes,
			expires_at, revoked_at, rotated_from_id, replaced_by_id,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, NULL, NOW(), NOW())`,
		m.ID,
		m.TokenHash,
		m.ClientID,
		m.UserID,
		m.Scopes,
		m.ExpiresAt,
		m.RotatedFromID,
	)
	if err != nil {
		return fmt.Errorf("oauth repo: create refresh token: %w", err)
	}

	return nil
}

func (r *OAuthRepository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*entity.OAuthRefreshToken, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrOAuthInvalidGrant
	}

	var m model.OAuthRefreshToken
	err := r.db.QueryRow(ctx, `
		SELECT id, token_hash, client_id, user_id, scopes,
		       expires_at, revoked_at, rotated_from_id, replaced_by_id,
		       created_at, updated_at
		FROM oauth_refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		LIMIT 1`, tokenHash).Scan(
		&m.ID,
		&m.TokenHash,
		&m.ClientID,
		&m.UserID,
		&m.Scopes,
		&m.ExpiresAt,
		&m.RevokedAt,
		&m.RotatedFromID,
		&m.ReplacedByID,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrOAuthInvalidGrant
		}
		return nil, fmt.Errorf("oauth repo: get refresh token by hash: %w", err)
	}

	return model.OAuthRefreshTokenModelToEntity(&m), nil
}

func (r *OAuthRepository) ConsumeRefreshToken(ctx context.Context, tokenHash string, replacedByID string, revokedAt time.Time) (*entity.OAuthRefreshToken, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrOAuthInvalidGrant
	}

	var m model.OAuthRefreshToken
	err := r.db.QueryRow(ctx, `
		UPDATE oauth_refresh_tokens
		SET revoked_at = $3,
		    replaced_by_id = $2,
		    updated_at = NOW()
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		RETURNING id, token_hash, client_id, user_id, scopes,
		          expires_at, revoked_at, rotated_from_id, replaced_by_id,
		          created_at, updated_at`,
		tokenHash,
		replacedByID,
		revokedAt,
	).Scan(
		&m.ID,
		&m.TokenHash,
		&m.ClientID,
		&m.UserID,
		&m.Scopes,
		&m.ExpiresAt,
		&m.RevokedAt,
		&m.RotatedFromID,
		&m.ReplacedByID,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err == nil {
		return model.OAuthRefreshTokenModelToEntity(&m), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("oauth repo: consume refresh token: %w", err)
	}

	var expiresAt time.Time
	var revoked *time.Time
	checkErr := r.db.QueryRow(ctx, `
		SELECT expires_at, revoked_at
		FROM oauth_refresh_tokens
		WHERE token_hash = $1
		LIMIT 1`, tokenHash).Scan(&expiresAt, &revoked)
	if checkErr != nil {
		if errors.Is(checkErr, pgx.ErrNoRows) {
			return nil, errorx.ErrOAuthInvalidGrant
		}
		return nil, fmt.Errorf("oauth repo: check refresh token state: %w", checkErr)
	}

	if revoked != nil {
		return nil, errorx.ErrOAuthReplayDetected
	}
	if !expiresAt.After(time.Now().UTC()) {
		return nil, errorx.ErrOAuthTokenExpired
	}

	return nil, errorx.ErrOAuthInvalidGrant
}

func (r *OAuthRepository) RevokeRefreshTokenByHash(ctx context.Context, tokenHash string, revokedAt time.Time) (bool, error) {
	if r == nil || r.db == nil {
		return false, errorx.ErrOAuthInvalidRequest
	}

	tag, err := r.db.Exec(ctx, `
		UPDATE oauth_refresh_tokens
		SET revoked_at = $2,
		    updated_at = NOW()
		WHERE token_hash = $1
		  AND revoked_at IS NULL`,
		tokenHash,
		revokedAt,
	)
	if err != nil {
		return false, fmt.Errorf("oauth repo: revoke refresh token: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}
