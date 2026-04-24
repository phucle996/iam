package repository

import (
	"context"
	"iam/internal/domain/entity"
	"iam/internal/model"
	"iam/pkg/errorx"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DeviceRepository persists Device, Challenge, and RefreshToken data.
type DeviceRepository struct {
	db *pgxpool.Pool
}

func NewDeviceRepository(db *pgxpool.Pool) *DeviceRepository {
	return &DeviceRepository{db: db}
}

// ── Core ─────────────────────────────────────────────────────────────────────

func (r *DeviceRepository) GetDeviceByFingerprint(ctx context.Context, userID, fingerprint string) (*entity.Device, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrDeviceNotFound
	}

	var (
		row        model.Device
		deviceName sql.NullString
		lastIP     sql.NullString
		revokedAt  sql.NullTime
	)

	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, device_public_key, key_algorithm, fingerprint,
		       device_name, last_ip, last_active_at, is_suspicious, revoked_at, created_at
		FROM devices
		WHERE user_id = $1 AND fingerprint = $2
		ORDER BY last_active_at DESC LIMIT 1`, userID, fingerprint).Scan(
		&row.ID, &row.UserID, &row.DevicePublicKey, &row.KeyAlgorithm, &row.Fingerprint,
		&deviceName, &lastIP, &row.LastActiveAt, &row.IsSuspicious, &revokedAt, &row.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrDeviceNotFound
		}
		return nil, fmt.Errorf("device repo: get by fingerprint: %w", err)
	}

	row.DeviceName = nullStr(deviceName)
	row.LastIP = nullStr(lastIP)
	if revokedAt.Valid {
		row.RevokedAt = &revokedAt.Time
	}

	return model.DeviceModelToEntity(&row), nil
}

func (r *DeviceRepository) GetDeviceByID(ctx context.Context, deviceID string) (*entity.Device, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrDeviceNotFound
	}

	var (
		row        model.Device
		deviceName sql.NullString
		lastIP     sql.NullString
		revokedAt  sql.NullTime
	)

	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, device_public_key, key_algorithm, fingerprint,
		       device_name, last_ip, last_active_at, is_suspicious, revoked_at, created_at
		FROM devices WHERE id = $1`, deviceID).Scan(
		&row.ID, &row.UserID, &row.DevicePublicKey, &row.KeyAlgorithm, &row.Fingerprint,
		&deviceName, &lastIP, &row.LastActiveAt, &row.IsSuspicious, &revokedAt, &row.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrDeviceNotFound
		}
		return nil, fmt.Errorf("device repo: get by id: %w", err)
	}

	row.DeviceName = nullStr(deviceName)
	row.LastIP = nullStr(lastIP)
	if revokedAt.Valid {
		row.RevokedAt = &revokedAt.Time
	}

	return model.DeviceModelToEntity(&row), nil
}

func (r *DeviceRepository) CreateDevice(ctx context.Context, device *entity.Device) error {
	if r == nil || r.db == nil {
		return errorx.ErrRegistrationFailed
	}

	d := model.DeviceEntityToModel(device)
	if d == nil {
		return errorx.ErrRegistrationFailed
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO devices (
			id, user_id, device_public_key, key_algorithm, fingerprint,
			device_name, last_ip, last_active_at, is_suspicious, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, false, NOW())`,
		d.ID, d.UserID, d.DevicePublicKey, d.KeyAlgorithm,
		d.Fingerprint, d.DeviceName, d.LastIP, d.LastActiveAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return errorx.ErrRegistrationFailed
		}
		return fmt.Errorf("device repo: create: %w", err)
	}

	return nil
}

func (r *DeviceRepository) UpdateDevice(ctx context.Context, device *entity.Device) error {
	if r == nil || r.db == nil || device == nil || device.ID == "" {
		return errorx.ErrDeviceNotFound
	}

	d := model.DeviceEntityToModel(device)
	if d == nil {
		return errorx.ErrDeviceNotFound
	}

	tag, err := r.db.Exec(ctx, `
		UPDATE devices
		SET device_public_key = $2,
		    key_algorithm     = $3,
		    fingerprint       = $4,
		    device_name       = $5,
		    last_ip           = $6,
		    last_active_at    = NOW()
		WHERE id = $1`,
		d.ID, d.DevicePublicKey, d.KeyAlgorithm,
		d.Fingerprint, d.DeviceName, d.LastIP,
	)
	if err != nil {
		return fmt.Errorf("device repo: update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrDeviceNotFound
	}

	return nil
}

func (r *DeviceRepository) CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	if r == nil || r.db == nil {
		return errorx.ErrRegistrationFailed
	}

	t := model.RefreshTokenEntityToModel(token)
	if t == nil {
		return errorx.ErrRegistrationFailed
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO refresh_tokens (
			id, device_id, user_id, token_hash, expires_at, is_revoked, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
		t.ID, t.DeviceID, t.UserID, t.TokenHash, t.ExpiresAt, t.IsRevoked,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return errorx.ErrRegistrationFailed
		}
		return fmt.Errorf("device repo: create refresh token: %w", err)
	}

	return nil
}

// ── User self-service ─────────────────────────────────────────────────────────

func (r *DeviceRepository) ListDevicesByUserID(ctx context.Context, userID string) ([]*entity.Device, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrDeviceNotFound
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, device_public_key, key_algorithm, fingerprint,
		       device_name, last_ip, last_active_at, is_suspicious, revoked_at, created_at
		FROM devices
		WHERE user_id = $1
		ORDER BY last_active_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("device repo: list by user: %w", err)
	}
	defer rows.Close()

	var devices []*entity.Device
	for rows.Next() {
		var (
			row        model.Device
			deviceName sql.NullString
			lastIP     sql.NullString
			revokedAt  sql.NullTime
		)
		if err := rows.Scan(
			&row.ID, &row.UserID, &row.DevicePublicKey, &row.KeyAlgorithm, &row.Fingerprint,
			&deviceName, &lastIP, &row.LastActiveAt, &row.IsSuspicious, &revokedAt, &row.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("device repo: scan: %w", err)
		}
		row.DeviceName = nullStr(deviceName)
		row.LastIP = nullStr(lastIP)
		if revokedAt.Valid {
			row.RevokedAt = &revokedAt.Time
		}
		devices = append(devices, model.DeviceModelToEntity(&row))
	}

	return devices, nil
}

func (r *DeviceRepository) DeleteDevice(ctx context.Context, deviceID string) error {
	if r == nil || r.db == nil {
		return errorx.ErrDeviceNotFound
	}

	tag, err := r.db.Exec(ctx, `DELETE FROM devices WHERE id = $1`, deviceID)
	if err != nil {
		return fmt.Errorf("device repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrDeviceNotFound
	}

	return nil
}

func (r *DeviceRepository) RevokeOtherDevices(ctx context.Context, userID, keepDeviceID string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errorx.ErrDeviceNotFound
	}

	tag, err := r.db.Exec(ctx,
		`DELETE FROM devices WHERE user_id = $1 AND id <> $2`,
		userID, keepDeviceID,
	)
	if err != nil {
		return 0, fmt.Errorf("device repo: revoke others: %w", err)
	}

	return tag.RowsAffected(), nil
}

// ── Security ──────────────────────────────────────────────────────────────────

func (r *DeviceRepository) SaveChallenge(ctx context.Context, ch *entity.DeviceChallenge) error {
	if r == nil || r.db == nil {
		return errorx.ErrDeviceChallengeInvalid
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO device_challenges (id, device_id, user_id, nonce, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,NOW())
		ON CONFLICT (device_id) DO UPDATE
		  SET id=$1, nonce=$4, expires_at=$5, created_at=NOW()`,
		ch.ChallengeID, ch.DeviceID, ch.UserID, ch.Nonce, ch.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("device repo: save challenge: %w", err)
	}

	return nil
}

func (r *DeviceRepository) GetChallenge(ctx context.Context, challengeID string) (*entity.DeviceChallenge, error) {
	if r == nil || r.db == nil {
		return nil, errorx.ErrDeviceChallengeNotFound
	}

	var ch entity.DeviceChallenge
	err := r.db.QueryRow(ctx, `
		SELECT id, device_id, user_id, nonce, expires_at, created_at
		FROM device_challenges WHERE id = $1`, challengeID).Scan(
		&ch.ChallengeID, &ch.DeviceID, &ch.UserID, &ch.Nonce, &ch.ExpiresAt, &ch.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrDeviceChallengeNotFound
		}
		return nil, fmt.Errorf("device repo: get challenge: %w", err)
	}

	return &ch, nil
}

func (r *DeviceRepository) DeleteChallenge(ctx context.Context, challengeID string) error {
	if r == nil || r.db == nil {
		return nil
	}

	_, err := r.db.Exec(ctx, `DELETE FROM device_challenges WHERE id = $1`, challengeID)
	if err != nil {
		return fmt.Errorf("device repo: delete challenge: %w", err)
	}

	return nil
}

func (r *DeviceRepository) RotateDeviceKey(ctx context.Context, deviceID, newPublicKey, newAlgorithm string) error {
	if r == nil || r.db == nil {
		return errorx.ErrDeviceKeyRotateFailed
	}

	tag, err := r.db.Exec(ctx, `
		UPDATE devices
		SET device_public_key = $2, key_algorithm = $3
		WHERE id = $1`,
		deviceID, newPublicKey, newAlgorithm,
	)
	if err != nil {
		return fmt.Errorf("device repo: rotate key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrDeviceNotFound
	}

	return nil
}

func (r *DeviceRepository) RevokeAllTokensByDevice(ctx context.Context, deviceID string) error {
	if r == nil || r.db == nil {
		return nil
	}

	_, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET is_revoked = true WHERE device_id = $1`,
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("device repo: revoke tokens by device: %w", err)
	}

	return nil
}

// ── Admin ─────────────────────────────────────────────────────────────────────

func (r *DeviceRepository) SetSuspicious(ctx context.Context, deviceID string, suspicious bool) error {
	if r == nil || r.db == nil {
		return errorx.ErrDeviceNotFound
	}

	tag, err := r.db.Exec(ctx,
		`UPDATE devices SET is_suspicious = $2 WHERE id = $1`,
		deviceID, suspicious,
	)
	if err != nil {
		return fmt.Errorf("device repo: set suspicious: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errorx.ErrDeviceNotFound
	}

	return nil
}

func (r *DeviceRepository) CleanupStaleDevices(ctx context.Context, before time.Time) (int64, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}

	tag, err := r.db.Exec(ctx,
		`DELETE FROM devices WHERE last_active_at < $1`,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("device repo: cleanup stale: %w", err)
	}

	return tag.RowsAffected(), nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func nullStr(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}
