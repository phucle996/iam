package repository

import (
	"context"
	"iam/internal/security"
	"iam/pkg/id"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecretRepository implements security.SecretProvider using Postgres.
type SecretRepository struct {
	db        *pgxpool.Pool
	masterKey string
}

func NewSecretRepository(db *pgxpool.Pool, masterKey string) *SecretRepository {
	return &SecretRepository{
		db:        db,
		masterKey: masterKey,
	}
}

func (r *SecretRepository) GetActive(family string) (security.SecretVersion, error) {

	var v security.SecretVersion
	err := r.db.QueryRow(context.Background(), `
		SELECT family, version, secret_ciphertext, expires_at, rotated_at
		FROM secret_key_versions
		WHERE family = $1 AND state = 'active'
		LIMIT 1
	`, family).Scan(&v.Family, &v.Version, &v.Value, &v.ExpiresAt, &v.RotatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			return security.SecretVersion{}, security.ErrSecretUnavailable
		}
		return security.SecretVersion{}, fmt.Errorf("secret repo: get active: %w", err)
	}

	plain, err := security.DecryptSecret(v.Value, r.masterKey)
	if err != nil {
		return security.SecretVersion{}, fmt.Errorf("secret repo: decrypt active: %w", err)
	}
	v.Value = plain

	return v, nil
}

func (r *SecretRepository) GetCandidates(family string) ([]security.SecretVersion, error) {
	if r == nil || r.db == nil {
		return nil, security.ErrSecretUnavailable
	}

	rows, err := r.db.Query(context.Background(), `
		SELECT family, version, secret_ciphertext, expires_at, rotated_at
		FROM secret_key_versions
		WHERE family = $1
		ORDER BY version DESC
	`, family)
	if err != nil {
		return nil, fmt.Errorf("secret repo: get candidates: %w", err)
	}
	defer rows.Close()

	var candidates []security.SecretVersion
	for rows.Next() {
		var v security.SecretVersion
		if err := rows.Scan(&v.Family, &v.Version, &v.Value, &v.ExpiresAt, &v.RotatedAt); err != nil {
			return nil, err
		}

		plain, err := security.DecryptSecret(v.Value, r.masterKey)
		if err != nil {
			return nil, fmt.Errorf("secret repo: decrypt candidate: %w", err)
		}
		v.Value = plain

		candidates = append(candidates, v)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("secret repo: iterate candidates: %w", err)
	}
	return candidates, nil
}
func (r *SecretRepository) CreateSecretVersion(ctx context.Context, v security.SecretVersion) error {
	if r == nil || r.db == nil {
		return security.ErrSecretUnavailable
	}

	id, err := id.Generate()
	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO secret_key_versions (
			id, family, version, state, secret_ciphertext, expires_at, rotated_at, created_at, updated_at
		) VALUES ($1, $2, $3, 'active', $4, $5, $6, NOW(), NOW())
	`, id, v.Family, v.Version, v.Value, v.ExpiresAt, v.RotatedAt)

	if err != nil {
		return fmt.Errorf("secret repo: create: %w", err)
	}
	return nil
}

func (r *SecretRepository) HasAny(ctx context.Context, family string) (bool, error) {
	if r == nil || r.db == nil {
		return false, security.ErrSecretUnavailable
	}

	var exists bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM secret_key_versions WHERE family = $1)
	`, family).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("secret repo: has any: %w", err)
	}
	return exists, nil
}

func (r *SecretRepository) RotateFamily(ctx context.Context, family string, overlap time.Duration) (int64, error) {
	if r == nil || r.db == nil {
		return 0, security.ErrSecretUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if overlap <= 0 {
		overlap = 24 * time.Hour
	}

	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("secret repo: begin rotate tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var currentVersion int64
	if err := tx.QueryRow(ctx, `
		SELECT version
		FROM secret_key_versions
		WHERE family = $1 AND state = 'active'
		FOR UPDATE
	`, family).Scan(&currentVersion); err != nil {
		if err == pgx.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("secret repo: read active version: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE secret_key_versions
		SET state = 'previous',
		    expires_at = NOW() + $2::interval,
		    updated_at = NOW()
		WHERE family = $1
		  AND state = 'active'
	`, family, formatInterval(overlap)); err != nil {
		return 0, fmt.Errorf("secret repo: demote active secret: %w", err)
	}

	nextVersion := currentVersion + 1
	rawSecret, err := security.GenerateToken(48, r.masterKey)
	if err != nil {
		return 0, fmt.Errorf("secret repo: generate new secret: %w", err)
	}
	secretCipher, err := security.EncryptSecret(rawSecret, r.masterKey)
	if err != nil {
		return 0, fmt.Errorf("secret repo: encrypt new secret: %w", err)
	}
	secretID, err := id.Generate()
	if err != nil {
		return 0, fmt.Errorf("secret repo: generate new secret id: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO secret_key_versions (
			id, family, version, state, secret_ciphertext, expires_at, rotated_at, created_at, updated_at
		) VALUES ($1, $2, $3, 'active', $4, $5, NOW(), NOW(), NOW())
	`, secretID, family, nextVersion, secretCipher, time.Now().UTC().AddDate(10, 0, 0)); err != nil {
		return 0, fmt.Errorf("secret repo: insert new active secret: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM secret_key_versions
		WHERE family = $1
		  AND state = 'previous'
		  AND expires_at <= NOW()
	`, family); err != nil {
		return 0, fmt.Errorf("secret repo: purge expired previous secrets: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("secret repo: commit rotate tx: %w", err)
	}
	return nextVersion, nil
}

func (r *SecretRepository) PromotePrevious(ctx context.Context, family string, previousVersion int64, overlap time.Duration) error {
	if r == nil || r.db == nil {
		return security.ErrSecretUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if overlap <= 0 {
		overlap = 24 * time.Hour
	}

	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("secret repo: begin rollback tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM secret_key_versions
			WHERE family = $1
			  AND version = $2
			  AND state = 'previous'
		)
	`, family, previousVersion).Scan(&exists); err != nil {
		return fmt.Errorf("secret repo: check rollback target: %w", err)
	}
	if !exists {
		return fmt.Errorf("secret repo: previous version not found for rollback")
	}

	if _, err := tx.Exec(ctx, `
		UPDATE secret_key_versions
		SET state = 'previous',
		    expires_at = NOW() + $2::interval,
		    updated_at = NOW()
		WHERE family = $1
		  AND state = 'active'
	`, family, formatInterval(overlap)); err != nil {
		return fmt.Errorf("secret repo: demote current active during rollback: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE secret_key_versions
		SET state = 'active',
		    expires_at = $3,
		    rotated_at = NOW(),
		    updated_at = NOW()
		WHERE family = $1
		  AND version = $2
		  AND state = 'previous'
	`, family, previousVersion, time.Now().UTC().AddDate(10, 0, 0)); err != nil {
		return fmt.Errorf("secret repo: promote previous secret: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM secret_key_versions
		WHERE family = $1
		  AND state = 'previous'
		  AND expires_at <= NOW()
	`, family); err != nil {
		return fmt.Errorf("secret repo: purge expired previous secrets: %w", err)
	}

	return tx.Commit(ctx)
}

func formatInterval(d time.Duration) string {
	return fmt.Sprintf("%f seconds", d.Seconds())
}
