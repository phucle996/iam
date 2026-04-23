DROP TRIGGER IF EXISTS set_timestamp_users ON users;
DROP TRIGGER IF EXISTS set_timestamp_user_profiles ON user_profiles;
DROP TRIGGER IF EXISTS set_timestamp_mfa_settings ON mfa_settings;
DROP TRIGGER IF EXISTS set_timestamp_roles ON roles;
DROP TRIGGER IF EXISTS set_timestamp_oauth_clients ON oauth_clients;
DROP TRIGGER IF EXISTS trim_audit_logs_30_days ON audit_logs;
DROP TRIGGER IF EXISTS set_timestamp_secret_key_versions ON secret_key_versions;

DROP FUNCTION IF EXISTS trigger_trim_audit_logs();
DROP FUNCTION IF EXISTS trigger_set_timestamp();
