
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
