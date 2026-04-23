CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
	NEW.updated_at = NOW();
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION trigger_trim_audit_logs()
RETURNS TRIGGER AS $$
BEGIN
	DELETE FROM audit_logs
	WHERE created_at < NOW() - INTERVAL '30 days';
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers
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

DROP TRIGGER IF EXISTS trim_audit_logs_30_days ON audit_logs;
CREATE TRIGGER trim_audit_logs_30_days
AFTER INSERT ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION trigger_trim_audit_logs();

DROP TRIGGER IF EXISTS set_timestamp_secret_key_versions ON secret_key_versions;
CREATE TRIGGER set_timestamp_secret_key_versions
BEFORE UPDATE ON secret_key_versions
FOR EACH ROW
EXECUTE FUNCTION trigger_set_timestamp();
