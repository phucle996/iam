
DROP TRIGGER IF EXISTS trim_audit_logs_30_days ON audit_logs;
DROP TRIGGER IF EXISTS set_timestamp_admin_sessions ON admin_sessions;
DROP TRIGGER IF EXISTS set_timestamp_admin_devices ON admin_devices;
DROP TRIGGER IF EXISTS set_timestamp_admin_mfa_methods ON admin_mfa_methods;
DROP TRIGGER IF EXISTS set_timestamp_admin_api_credentials ON admin_api_credentials;
DROP TRIGGER IF EXISTS set_timestamp_admin_users ON admin_users;
DROP TRIGGER IF EXISTS set_timestamp_secret_key_versions ON secret_key_versions;
DROP TRIGGER IF EXISTS set_timestamp_oauth_refresh_tokens ON oauth_refresh_tokens;
DROP TRIGGER IF EXISTS set_timestamp_oauth_clients ON oauth_clients;
DROP TRIGGER IF EXISTS set_timestamp_roles ON roles;
DROP TRIGGER IF EXISTS set_timestamp_mfa_settings ON mfa_settings;
DROP TRIGGER IF EXISTS set_timestamp_devices ON devices;
DROP TRIGGER IF EXISTS set_timestamp_user_profiles ON user_profiles;
DROP TRIGGER IF EXISTS set_timestamp_users ON users;
