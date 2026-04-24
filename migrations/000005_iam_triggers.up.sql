
DROP TRIGGER IF EXISTS set_timestamp_users ON users;
CREATE TRIGGER set_timestamp_users
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_user_profiles ON user_profiles;
CREATE TRIGGER set_timestamp_user_profiles
BEFORE UPDATE ON user_profiles
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_devices ON devices;
CREATE TRIGGER set_timestamp_devices
BEFORE UPDATE ON devices
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_mfa_settings ON mfa_settings;
CREATE TRIGGER set_timestamp_mfa_settings
BEFORE UPDATE ON mfa_settings
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_roles ON roles;
CREATE TRIGGER set_timestamp_roles
BEFORE UPDATE ON roles
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_oauth_clients ON oauth_clients;
CREATE TRIGGER set_timestamp_oauth_clients
BEFORE UPDATE ON oauth_clients
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_oauth_refresh_tokens ON oauth_refresh_tokens;
CREATE TRIGGER set_timestamp_oauth_refresh_tokens
BEFORE UPDATE ON oauth_refresh_tokens
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_secret_key_versions ON secret_key_versions;
CREATE TRIGGER set_timestamp_secret_key_versions
BEFORE UPDATE ON secret_key_versions
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_admin_users ON admin_users;
CREATE TRIGGER set_timestamp_admin_users
BEFORE UPDATE ON admin_users
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_admin_api_credentials ON admin_api_credentials;
CREATE TRIGGER set_timestamp_admin_api_credentials
BEFORE UPDATE ON admin_api_credentials
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_admin_mfa_methods ON admin_mfa_methods;
CREATE TRIGGER set_timestamp_admin_mfa_methods
BEFORE UPDATE ON admin_mfa_methods
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_admin_devices ON admin_devices;
CREATE TRIGGER set_timestamp_admin_devices
BEFORE UPDATE ON admin_devices
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS set_timestamp_admin_sessions ON admin_sessions;
CREATE TRIGGER set_timestamp_admin_sessions
BEFORE UPDATE ON admin_sessions
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();

DROP TRIGGER IF EXISTS trim_audit_logs_30_days ON audit_logs;
CREATE TRIGGER trim_audit_logs_30_days
AFTER INSERT ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION trigger_trim_audit_logs();
