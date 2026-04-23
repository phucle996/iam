CREATE INDEX IF NOT EXISTS idx_iam_password_histories_user_id ON password_histories(user_id);
CREATE INDEX IF NOT EXISTS idx_iam_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_iam_refresh_tokens_device_id ON refresh_tokens(device_id);
CREATE INDEX IF NOT EXISTS idx_iam_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_iam_mfa_settings_user_id ON mfa_settings(user_id);
CREATE INDEX IF NOT EXISTS idx_iam_recovery_codes_user_id ON recovery_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_iam_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_iam_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_iam_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_iam_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_iam_audit_logs_created_at ON audit_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_iam_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_iam_refresh_tokens_expires_at ON refresh_tokens(expires_at);

CREATE INDEX IF NOT EXISTS idx_iam_devices_user_id_fingerprint_last_active_at
	ON devices(user_id, fingerprint, last_active_at DESC);

CREATE INDEX IF NOT EXISTS idx_secret_key_versions_family_state
  ON secret_key_versions(family, state);

CREATE INDEX IF NOT EXISTS idx_secret_key_versions_family_rotated_at
  ON secret_key_versions(family, rotated_at DESC);
