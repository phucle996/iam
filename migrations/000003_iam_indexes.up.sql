
CREATE INDEX IF NOT EXISTS idx_iam_password_histories_user_id
	ON password_histories(user_id);

CREATE INDEX IF NOT EXISTS idx_iam_devices_user_id
	ON devices(user_id);

CREATE INDEX IF NOT EXISTS idx_iam_devices_user_id_fingerprint_last_active_at
	ON devices(user_id, fingerprint, last_active_at DESC);

CREATE INDEX IF NOT EXISTS idx_iam_refresh_tokens_device_id
	ON refresh_tokens(device_id);

CREATE INDEX IF NOT EXISTS idx_iam_refresh_tokens_user_id
	ON refresh_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_iam_refresh_tokens_expires_at
	ON refresh_tokens(expires_at);

CREATE INDEX IF NOT EXISTS idx_iam_webauthn_credentials_user_id
	ON webauthn_credentials(user_id);

CREATE INDEX IF NOT EXISTS idx_iam_mfa_settings_user_id
	ON mfa_settings(user_id);

CREATE INDEX IF NOT EXISTS idx_iam_recovery_codes_user_id
	ON recovery_codes(user_id);

CREATE INDEX IF NOT EXISTS idx_iam_role_permissions_permission_id
	ON role_permissions(permission_id);

CREATE INDEX IF NOT EXISTS idx_iam_user_roles_role_id
	ON user_roles(role_id);

CREATE INDEX IF NOT EXISTS idx_iam_oauth_authorization_codes_client_id
	ON oauth_authorization_codes(client_id);

CREATE INDEX IF NOT EXISTS idx_iam_oauth_authorization_codes_user_id
	ON oauth_authorization_codes(user_id);

CREATE INDEX IF NOT EXISTS idx_iam_oauth_authorization_codes_expires_at
	ON oauth_authorization_codes(expires_at);

CREATE INDEX IF NOT EXISTS idx_iam_oauth_authorization_codes_active
	ON oauth_authorization_codes(code_hash)
	WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_iam_oauth_refresh_tokens_client_id
	ON oauth_refresh_tokens(client_id);

CREATE INDEX IF NOT EXISTS idx_iam_oauth_refresh_tokens_user_id
	ON oauth_refresh_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_iam_oauth_refresh_tokens_expires_at
	ON oauth_refresh_tokens(expires_at);

CREATE INDEX IF NOT EXISTS idx_iam_oauth_refresh_tokens_active
	ON oauth_refresh_tokens(token_hash)
	WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_iam_oauth_refresh_tokens_rotated_from
	ON oauth_refresh_tokens(rotated_from_id);

CREATE INDEX IF NOT EXISTS idx_iam_oauth_refresh_tokens_replaced_by
	ON oauth_refresh_tokens(replaced_by_id);

CREATE INDEX IF NOT EXISTS idx_iam_audit_logs_user_id
	ON audit_logs(user_id);

CREATE INDEX IF NOT EXISTS idx_iam_audit_logs_action
	ON audit_logs(action);

CREATE INDEX IF NOT EXISTS idx_iam_audit_logs_created_at
	ON audit_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_iam_admin_api_credentials_admin_user_id
	ON admin_api_credentials(admin_user_id);

CREATE INDEX IF NOT EXISTS idx_iam_admin_api_credentials_expires_at
	ON admin_api_credentials(expires_at);

CREATE INDEX IF NOT EXISTS idx_iam_admin_mfa_methods_admin_user_id
	ON admin_mfa_methods(admin_user_id);

CREATE INDEX IF NOT EXISTS idx_iam_admin_mfa_methods_status
	ON admin_mfa_methods(status);

CREATE INDEX IF NOT EXISTS idx_iam_admin_devices_admin_user_id
	ON admin_devices(admin_user_id);

CREATE INDEX IF NOT EXISTS idx_iam_admin_devices_credential_id
	ON admin_devices(credential_id);

CREATE INDEX IF NOT EXISTS idx_iam_admin_devices_status_trusted_until
	ON admin_devices(status, trusted_until);

CREATE INDEX IF NOT EXISTS idx_iam_admin_sessions_admin_user_id
	ON admin_sessions(admin_user_id);

CREATE INDEX IF NOT EXISTS idx_iam_admin_sessions_credential_id
	ON admin_sessions(credential_id);

CREATE INDEX IF NOT EXISTS idx_iam_admin_sessions_device_id
	ON admin_sessions(device_id);

CREATE INDEX IF NOT EXISTS idx_iam_admin_sessions_status_expires_at
	ON admin_sessions(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_secret_key_versions_family_state
	ON secret_key_versions(family, state);

CREATE INDEX IF NOT EXISTS idx_secret_key_versions_family_rotated_at
	ON secret_key_versions(family, rotated_at DESC);
