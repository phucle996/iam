
CREATE TABLE IF NOT EXISTS users (
	id VARCHAR(26) PRIMARY KEY,
	username VARCHAR(255) NOT NULL,
	email VARCHAR(255) NOT NULL,
	phone VARCHAR(20),
	password_hash TEXT NOT NULL,
	security_level SMALLINT NOT NULL CHECK (security_level >= 0),
	status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disable')),
	status_reason VARCHAR(255),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT users_username_key UNIQUE (username),
	CONSTRAINT users_email_key UNIQUE (email),
	CONSTRAINT users_phone_key UNIQUE (phone)
);

CREATE TABLE IF NOT EXISTS user_profiles (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	fullname VARCHAR(100),
	avatar_url TEXT,
	bio TEXT,
	timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT user_profiles_user_id_key UNIQUE (user_id)
);

CREATE TABLE IF NOT EXISTS password_histories (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	password_hash TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS devices (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	device_public_key TEXT NOT NULL,
	key_algorithm VARCHAR(20) NOT NULL DEFAULT 'ES256',
	fingerprint TEXT NOT NULL,
	device_name VARCHAR(100),
	last_ip INET,
	last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	is_suspicious BOOLEAN NOT NULL DEFAULT FALSE,
	revoked_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_challenges (
	id VARCHAR(26) PRIMARY KEY,
	device_id VARCHAR(26) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	nonce TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT device_challenges_device_id_key UNIQUE (device_id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	id VARCHAR(26) PRIMARY KEY,
	device_id VARCHAR(26) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	token_hash TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	credential_id TEXT NOT NULL,
	public_key TEXT NOT NULL,
	sign_count BIGINT NOT NULL DEFAULT 0,
	device_name VARCHAR(100),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT webauthn_credentials_credential_id_key UNIQUE (credential_id)
);

CREATE TABLE IF NOT EXISTS mfa_settings (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	mfa_type VARCHAR(50) NOT NULL,
	device_name VARCHAR(100),
	is_primary BOOLEAN NOT NULL DEFAULT FALSE,
	secret_encrypted TEXT NOT NULL,
	is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS recovery_codes (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	code_hash TEXT NOT NULL,
	is_used BOOLEAN NOT NULL DEFAULT FALSE,
	used_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
	id VARCHAR(26) PRIMARY KEY,
	name VARCHAR(100) NOT NULL,
	level INTEGER NOT NULL DEFAULT 100,
	description TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT roles_name_key UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS permissions (
	id VARCHAR(26) PRIMARY KEY,
	name VARCHAR(100) NOT NULL DEFAULT '',
	slug VARCHAR(100),
	description TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT permissions_name_key UNIQUE (name),
	CONSTRAINT permissions_slug_key UNIQUE (slug)
);

CREATE TABLE IF NOT EXISTS role_permissions (
	role_id VARCHAR(26) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
	permission_id VARCHAR(26) NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
	PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role_id VARCHAR(26) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
	PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS oauth_clients (
	id VARCHAR(26) PRIMARY KEY,
	client_id VARCHAR(100) NOT NULL,
	client_secret_hash TEXT NOT NULL,
	name VARCHAR(100) NOT NULL,
	redirect_uris JSONB NOT NULL,
	allowed_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
	is_active BOOLEAN NOT NULL DEFAULT TRUE,
	secret_rotated_at TIMESTAMPTZ,
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT oauth_clients_client_id_key UNIQUE (client_id)
);

CREATE TABLE IF NOT EXISTS oauth_grants (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	client_id VARCHAR(26) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	scopes JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT oauth_grants_user_id_client_id_key UNIQUE (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
	id VARCHAR(26) PRIMARY KEY,
	code_hash TEXT NOT NULL,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	client_id VARCHAR(26) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	redirect_uri TEXT NOT NULL,
	scopes JSONB,
	code_challenge TEXT NOT NULL,
	code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256' CHECK (code_challenge_method IN ('S256')),
	expires_at TIMESTAMPTZ NOT NULL,
	consumed_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT oauth_authorization_codes_code_hash_key UNIQUE (code_hash)
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
	id VARCHAR(26) PRIMARY KEY,
	token_hash TEXT NOT NULL,
	client_id VARCHAR(26) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	user_id VARCHAR(26) REFERENCES users(id) ON DELETE CASCADE,
	scopes JSONB,
	expires_at TIMESTAMPTZ NOT NULL,
	revoked_at TIMESTAMPTZ,
	rotated_from_id VARCHAR(26) REFERENCES oauth_refresh_tokens(id) ON DELETE SET NULL,
	replaced_by_id VARCHAR(26) REFERENCES oauth_refresh_tokens(id) ON DELETE SET NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT oauth_refresh_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE TABLE IF NOT EXISTS audit_logs (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) REFERENCES users(id) ON DELETE SET NULL,
	action VARCHAR(100) NOT NULL,
	risk_level SMALLINT NOT NULL DEFAULT 1,
	ip_address INET,
	user_agent TEXT,
	device_id VARCHAR(26),
	metadata JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_users (
	id VARCHAR(26) PRIMARY KEY,
	display_name VARCHAR(120) NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_api_credentials (
	id VARCHAR(26) PRIMARY KEY,
	admin_user_id VARCHAR(26) NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	token_hash TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	last_used_at TIMESTAMPTZ,
	is_suspicious BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT admin_api_credentials_token_hash_key UNIQUE (token_hash)
);

CREATE TABLE IF NOT EXISTS admin_mfa_methods (
	id VARCHAR(26) PRIMARY KEY,
	admin_user_id VARCHAR(26) NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	method VARCHAR(32) NOT NULL CHECK (method IN ('totp', 'recovery')),
	status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
	secret_encrypted TEXT NOT NULL DEFAULT '',
	code_hash TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_devices (
	id VARCHAR(26) PRIMARY KEY,
	admin_user_id VARCHAR(26) NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	credential_id VARCHAR(26) NOT NULL REFERENCES admin_api_credentials(id) ON DELETE CASCADE,
	device_secret_hash TEXT NOT NULL,
	status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'suspicious')),
	trusted_until TIMESTAMPTZ,
	last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_seen_ip INET,
	user_agent TEXT,
	is_suspicious BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_sessions (
	id VARCHAR(26) PRIMARY KEY,
	admin_user_id VARCHAR(26) NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	credential_id VARCHAR(26) NOT NULL REFERENCES admin_api_credentials(id) ON DELETE CASCADE,
	device_id VARCHAR(26) NOT NULL REFERENCES admin_devices(id) ON DELETE CASCADE,
	session_token_hash TEXT NOT NULL,
	status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired', 'suspicious')),
	expires_at TIMESTAMPTZ NOT NULL,
	revoked_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT admin_sessions_token_hash_key UNIQUE (session_token_hash)
);

CREATE TABLE IF NOT EXISTS admin_api_tokens (
	id VARCHAR(26) PRIMARY KEY,
	token_hash TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT admin_api_tokens_token_hash_key UNIQUE (token_hash)
);

CREATE TABLE IF NOT EXISTS secret_key_versions (
	id VARCHAR(26) PRIMARY KEY,
	family VARCHAR(32) NOT NULL,
	version BIGINT NOT NULL CHECK (version > 0),
	state VARCHAR(16) NOT NULL CHECK (state IN ('active', 'previous')),
	secret_ciphertext TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT secret_key_versions_family_version_key UNIQUE (family, version),
	CONSTRAINT secret_key_versions_family_state_key UNIQUE (family, state)
);

ALTER TABLE secret_key_versions
	DROP CONSTRAINT IF EXISTS secret_key_versions_family_check;

ALTER TABLE secret_key_versions
	ADD CONSTRAINT secret_key_versions_family_check CHECK (
		family IN ('access', 'refresh', 'one_time', 'admin_api', 'oauth_access', 'oauth_refresh')
	);
