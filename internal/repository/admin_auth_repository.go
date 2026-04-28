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
	"github.com/jackc/pgx/v5/pgxpool"
)

type AdminAuthRepository struct {
	db *pgxpool.Pool
}

func NewAdminAuthRepository(db *pgxpool.Pool) *AdminAuthRepository {
	return &AdminAuthRepository{db: db}
}

func (r *AdminAuthRepository) HasAdminCredentials(ctx context.Context) (bool, error) {
	if r == nil || r.db == nil {
		return false, fmt.Errorf("iam repo: admin auth db is nil")
	}

	var exists bool
	if err := r.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM admin_api_credentials
		)
	`).Scan(&exists); err != nil {
		return false, fmt.Errorf("iam repo: has admin credentials: %w", err)
	}
	return exists, nil
}

func (r *AdminAuthRepository) CreateBootstrapAdmin(ctx context.Context, admin *entity.AdminUser, credential *entity.AdminAPICredential, mfaMethods []*entity.AdminMFAMethod) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin auth db is nil")
	}
	dbAdmin := model.AdminUserEntityToModel(admin)
	dbCredential := model.AdminAPICredentialEntityToModel(credential)
	if dbAdmin == nil || dbCredential == nil {
		return fmt.Errorf("iam repo: bootstrap admin model is nil")
	}

	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("iam repo: begin bootstrap admin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_users (id, display_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4)
	`, dbAdmin.ID, dbAdmin.DisplayName, dbAdmin.CreatedAt, dbAdmin.UpdatedAt); err != nil {
		return fmt.Errorf("iam repo: create bootstrap admin user: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_api_credentials (
			id, admin_user_id, token_hash,
			expires_at, last_used_at, is_suspicious, created_at, updated_at
		) VALUES (
			$1, $2, $3,
			$4, $5, $6, $7, $8
		)
	`, dbCredential.ID, dbCredential.AdminUserID, dbCredential.TokenHash,
		dbCredential.ExpiresAt, dbCredential.LastUsedAt, dbCredential.Suspicious, dbCredential.CreatedAt, dbCredential.UpdatedAt); err != nil {
		return fmt.Errorf("iam repo: create bootstrap admin credential: %w", err)
	}

	for _, mfa := range mfaMethods {
		dbMFA := model.AdminMFAMethodEntityToModel(mfa)
		if dbMFA == nil {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO admin_mfa_methods (
				id, admin_user_id, method, status, secret_encrypted, code_hash, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, dbMFA.ID, dbMFA.AdminUserID, dbMFA.Method, dbMFA.Status, dbMFA.SecretEncrypted, dbMFA.CodeHash, dbMFA.CreatedAt, dbMFA.UpdatedAt); err != nil {
			return fmt.Errorf("iam repo: create bootstrap admin mfa: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("iam repo: commit bootstrap admin tx: %w", err)
	}
	return nil
}

func (r *AdminAuthRepository) GetCredentialByHash(ctx context.Context, tokenHash string, now time.Time) (*entity.AdminAPICredential, *entity.AdminUser, error) {
	if r == nil || r.db == nil {
		return nil, nil, fmt.Errorf("iam repo: admin auth db is nil")
	}

	var credential model.AdminAPICredential
	var admin model.AdminUser
	err := r.db.QueryRow(ctx, `
		SELECT
			c.id, c.admin_user_id, c.token_hash,
			c.expires_at, c.last_used_at, c.is_suspicious, c.created_at, c.updated_at,
			u.id, u.display_name, u.created_at, u.updated_at
		FROM admin_api_credentials c
		JOIN admin_users u ON u.id = c.admin_user_id
		WHERE c.token_hash = $1
		  AND c.expires_at > $2
		  AND c.is_suspicious = FALSE
		LIMIT 1
	`, tokenHash, now).Scan(
		&credential.ID, &credential.AdminUserID, &credential.TokenHash,
		&credential.ExpiresAt, &credential.LastUsedAt, &credential.Suspicious, &credential.CreatedAt, &credential.UpdatedAt,
		&admin.ID, &admin.DisplayName, &admin.CreatedAt, &admin.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, errorx.ErrAdminAuthInvalid
		}
		return nil, nil, fmt.Errorf("iam repo: get admin credential by hash: %w", err)
	}
	return model.AdminAPICredentialModelToEntity(&credential), model.AdminUserModelToEntity(&admin), nil
}

func (r *AdminAuthRepository) ListMFAMethods(ctx context.Context, adminUserID string) ([]*entity.AdminMFAMethod, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("iam repo: admin auth db is nil")
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, admin_user_id, method, status, COALESCE(secret_encrypted, ''), COALESCE(code_hash, ''), created_at, updated_at
		FROM admin_mfa_methods
		WHERE admin_user_id = $1
		ORDER BY created_at ASC
	`, adminUserID)
	if err != nil {
		return nil, fmt.Errorf("iam repo: list admin mfa methods: %w", err)
	}
	defer rows.Close()

	var methods []*entity.AdminMFAMethod
	for rows.Next() {
		var method model.AdminMFAMethod
		if err := rows.Scan(
			&method.ID, &method.AdminUserID, &method.Method, &method.Status, &method.SecretEncrypted, &method.CodeHash,
			&method.CreatedAt, &method.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("iam repo: scan admin mfa method: %w", err)
		}
		methods = append(methods, model.AdminMFAMethodModelToEntity(&method))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iam repo: iterate admin mfa methods: %w", err)
	}
	return methods, nil
}

func (r *AdminAuthRepository) DisableMFAMethod(ctx context.Context, methodID string) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin auth db is nil")
	}

	_, err := r.db.Exec(ctx, `
		UPDATE admin_mfa_methods
		SET status = $2, updated_at = NOW()
		WHERE id = $1
	`, methodID, entity.AdminMFAStatusDisabled)
	if err != nil {
		return fmt.Errorf("iam repo: disable admin mfa method: %w", err)
	}
	return nil
}

func (r *AdminAuthRepository) GetDeviceByID(ctx context.Context, deviceID string) (*entity.AdminDevice, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("iam repo: admin auth db is nil")
	}

	var device model.AdminDevice
	err := r.db.QueryRow(ctx, `
		SELECT
			id, admin_user_id, credential_id, device_secret_hash, status,
			trusted_until, last_seen_at, COALESCE(last_seen_ip::text, ''),
			COALESCE(user_agent, ''), is_suspicious, created_at, updated_at
		FROM admin_devices
		WHERE id = $1
		LIMIT 1
	`, deviceID).Scan(
		&device.ID, &device.AdminUserID, &device.CredentialID, &device.DeviceSecretHash, &device.Status,
		&device.TrustedUntil, &device.LastSeenAt, &device.LastSeenIP, &device.UserAgent,
		&device.Suspicious, &device.CreatedAt, &device.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errorx.ErrAdminDeviceInvalid
		}
		return nil, fmt.Errorf("iam repo: get admin device: %w", err)
	}
	return model.AdminDeviceModelToEntity(&device), nil
}

func (r *AdminAuthRepository) CreateDevice(ctx context.Context, device *entity.AdminDevice) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin auth db is nil")
	}
	dbDevice := model.AdminDeviceEntityToModel(device)
	if dbDevice == nil {
		return fmt.Errorf("iam repo: admin device model is nil")
	}

	if _, err := r.db.Exec(ctx, `
		INSERT INTO admin_devices (
			id, admin_user_id, credential_id, device_secret_hash, status,
			trusted_until, last_seen_at, last_seen_ip, user_agent, is_suspicious,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, NULLIF($8, '')::inet, $9, $10,
			$11, $12
		)
	`, dbDevice.ID, dbDevice.AdminUserID, dbDevice.CredentialID, dbDevice.DeviceSecretHash, dbDevice.Status,
		dbDevice.TrustedUntil, dbDevice.LastSeenAt, dbDevice.LastSeenIP, dbDevice.UserAgent,
		dbDevice.Suspicious, dbDevice.CreatedAt, dbDevice.UpdatedAt); err != nil {
		return fmt.Errorf("iam repo: create admin device: %w", err)
	}
	return nil
}

func (r *AdminAuthRepository) TrustDevice(ctx context.Context, deviceID string, trustedUntil time.Time) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin auth db is nil")
	}
	if _, err := r.db.Exec(ctx, `
		UPDATE admin_devices
		SET trusted_until = $2,
		    updated_at = NOW()
		WHERE id = $1
		  AND status = 'active'
	`, deviceID, trustedUntil); err != nil {
		return fmt.Errorf("iam repo: trust admin device: %w", err)
	}
	return nil
}

func (r *AdminAuthRepository) TouchDevice(ctx context.Context, deviceID, ip string, seenAt time.Time) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin auth db is nil")
	}
	if _, err := r.db.Exec(ctx, `
		UPDATE admin_devices
		SET last_seen_at = $2,
		    last_seen_ip = NULLIF($3, '')::inet,
		    updated_at = NOW()
		WHERE id = $1
	`, deviceID, seenAt, ip); err != nil {
		return fmt.Errorf("iam repo: touch admin device: %w", err)
	}
	return nil
}

func (r *AdminAuthRepository) MarkDeviceSuspicious(ctx context.Context, deviceID string) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin auth db is nil")
	}
	if _, err := r.db.Exec(ctx, `
		UPDATE admin_devices
		SET status = 'suspicious',
		    is_suspicious = TRUE,
		    updated_at = NOW()
		WHERE id = $1
	`, deviceID); err != nil {
		return fmt.Errorf("iam repo: mark admin device suspicious: %w", err)
	}
	return nil
}

func (r *AdminAuthRepository) CreateSession(ctx context.Context, session *entity.AdminSession) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin auth db is nil")
	}
	dbSession := model.AdminSessionEntityToModel(session)
	if dbSession == nil {
		return fmt.Errorf("iam repo: admin session model is nil")
	}
	if _, err := r.db.Exec(ctx, `
		INSERT INTO admin_sessions (
			id, admin_user_id, credential_id, device_id, session_token_hash,
			status, expires_at, revoked_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10
		)
	`, dbSession.ID, dbSession.AdminUserID, dbSession.CredentialID, dbSession.DeviceID, dbSession.SessionTokenHash,
		dbSession.Status, dbSession.ExpiresAt, dbSession.RevokedAt, dbSession.CreatedAt, dbSession.UpdatedAt); err != nil {
		return fmt.Errorf("iam repo: create admin session: %w", err)
	}
	return nil
}

func (r *AdminAuthRepository) GetSessionByHash(ctx context.Context, sessionHash string, now time.Time) (*entity.AdminSession, *entity.AdminUser, *entity.AdminAPICredential, *entity.AdminDevice, error) {

	var session model.AdminSession
	var admin model.AdminUser
	var credential model.AdminAPICredential
	var device model.AdminDevice
	err := r.db.QueryRow(ctx, `
		SELECT
			s.id, s.admin_user_id, s.credential_id, s.device_id, s.session_token_hash,
			s.status, s.expires_at, s.revoked_at, s.created_at, s.updated_at,
			u.id, u.display_name, u.created_at, u.updated_at,
			c.id, c.admin_user_id, c.token_hash,
			c.expires_at, c.last_used_at, c.is_suspicious, c.created_at, c.updated_at,
			d.id, d.admin_user_id, d.credential_id, d.device_secret_hash, d.status,
			d.trusted_until, d.last_seen_at, COALESCE(d.last_seen_ip::text, ''),
			COALESCE(d.user_agent, ''), d.is_suspicious, d.created_at, d.updated_at
		FROM admin_sessions s
		JOIN admin_users u ON u.id = s.admin_user_id
		JOIN admin_api_credentials c ON c.id = s.credential_id
		JOIN admin_devices d ON d.id = s.device_id
		WHERE s.session_token_hash = $1
		  AND s.status = 'active'
		  AND s.revoked_at IS NULL
		  AND s.expires_at > $2
		  AND c.expires_at > $2
		  AND c.is_suspicious = FALSE
		  AND d.status = 'active'
		  AND d.is_suspicious = FALSE
		LIMIT 1
	`, sessionHash, now).Scan(
		&session.ID, &session.AdminUserID, &session.CredentialID, &session.DeviceID, &session.SessionTokenHash,
		&session.Status, &session.ExpiresAt, &session.RevokedAt, &session.CreatedAt, &session.UpdatedAt,
		&admin.ID, &admin.DisplayName, &admin.CreatedAt, &admin.UpdatedAt,
		&credential.ID, &credential.AdminUserID, &credential.TokenHash,
		&credential.ExpiresAt, &credential.LastUsedAt, &credential.Suspicious, &credential.CreatedAt, &credential.UpdatedAt,
		&device.ID, &device.AdminUserID, &device.CredentialID, &device.DeviceSecretHash, &device.Status,
		&device.TrustedUntil, &device.LastSeenAt, &device.LastSeenIP, &device.UserAgent,
		&device.Suspicious, &device.CreatedAt, &device.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil, nil, errorx.ErrAdminSessionInvalid
		}
		return nil, nil, nil, nil, fmt.Errorf("iam repo: get admin session by hash: %w", err)
	}
	return model.AdminSessionModelToEntity(&session),
		model.AdminUserModelToEntity(&admin),
		model.AdminAPICredentialModelToEntity(&credential),
		model.AdminDeviceModelToEntity(&device),
		nil
}

func (r *AdminAuthRepository) RevokeSession(ctx context.Context, sessionHash string, revokedAt time.Time) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin auth db is nil")
	}
	if _, err := r.db.Exec(ctx, `
		UPDATE admin_sessions
		SET status = 'revoked',
		    revoked_at = $2,
		    updated_at = NOW()
		WHERE session_token_hash = $1
		  AND status = 'active'
	`, sessionHash, revokedAt); err != nil {
		return fmt.Errorf("iam repo: revoke admin session: %w", err)
	}
	return nil
}

func (r *AdminAuthRepository) InsertAudit(ctx context.Context, audit *entity.AuditLog) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("iam repo: admin auth db is nil")
	}
	if audit == nil {
		return nil
	}

	var userID *string
	if audit.UserID != "" {
		userID = &audit.UserID
	}
	var ipAddress *string
	if audit.IPAddress != "" {
		ipAddress = &audit.IPAddress
	}
	var userAgent *string
	if audit.UserAgent != "" {
		userAgent = &audit.UserAgent
	}
	var deviceID *string
	if audit.DeviceID != "" {
		deviceID = &audit.DeviceID
	}
	if _, err := r.db.Exec(ctx, `
		INSERT INTO audit_logs (
			id, user_id, action, risk_level, ip_address, user_agent, device_id, metadata, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
	`, audit.ID, userID, audit.Action, audit.RiskLevel, ipAddress, userAgent, deviceID, audit.Metadata, audit.CreatedAt); err != nil {
		return fmt.Errorf("iam repo: insert admin audit: %w", err)
	}
	return nil
}
