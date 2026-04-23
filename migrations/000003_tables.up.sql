-- Users and Profiles
CREATE TABLE IF NOT EXISTS users (
	id VARCHAR(26) PRIMARY KEY,
	username VARCHAR(255) UNIQUE NOT NULL,
	email VARCHAR(255) UNIQUE NOT NULL,
	phone VARCHAR(20) UNIQUE,
	password_hash TEXT NOT NULL,
	security_level SMALLINT NOT NULL CHECK (security_level >= 0),
	status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disable')),
	status_reason VARCHAR(255),
	created_at TIMESTAMPTZ DEFAULT NOW(),
	updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_histories (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	password_hash TEXT NOT NULL,
	created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_profiles (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	fullname VARCHAR(100),
	avatar_url TEXT,
	bio TEXT,
	timezone VARCHAR(50) DEFAULT 'UTC',
	created_at TIMESTAMPTZ DEFAULT NOW(),
	updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Devices and Tokens
CREATE TABLE IF NOT EXISTS devices (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	device_public_key TEXT NOT NULL,
	key_algorithm VARCHAR(20) DEFAULT 'ES256',
	fingerprint TEXT NOT NULL,
	device_name VARCHAR(100),
	last_ip INET,
	last_active_at TIMESTAMPTZ DEFAULT NOW(),
	is_suspicious BOOLEAN NOT NULL DEFAULT FALSE,
	revoked_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_challenges (
	id VARCHAR(26) PRIMARY KEY,
	device_id VARCHAR(26) NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	nonce TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	id VARCHAR(26) PRIMARY KEY,
	device_id VARCHAR(26) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	token_hash TEXT NOT NULL UNIQUE,
	expires_at TIMESTAMPTZ NOT NULL,
	is_revoked BOOLEAN DEFAULT FALSE,
	created_at TIMESTAMPTZ DEFAULT NOW()
);

-- MFA
CREATE TABLE IF NOT EXISTS webauthn_credentials (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	credential_id TEXT UNIQUE NOT NULL,
	public_key TEXT NOT NULL,
	sign_count BIGINT DEFAULT 0,
	device_name VARCHAR(100),
	created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_settings (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	mfa_type VARCHAR(50) NOT NULL,
	device_name VARCHAR(100),
	is_primary BOOLEAN DEFAULT FALSE,
	secret_encrypted TEXT NOT NULL,
	is_enabled BOOLEAN DEFAULT FALSE,
	created_at TIMESTAMPTZ DEFAULT NOW(),
	updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS recovery_codes (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	code_hash TEXT NOT NULL,
	is_used BOOLEAN DEFAULT FALSE,
	used_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ DEFAULT NOW()
);

-- RBAC
CREATE TABLE IF NOT EXISTS roles (
	id VARCHAR(26) PRIMARY KEY,
	name VARCHAR(100) UNIQUE NOT NULL,
	level INTEGER NOT NULL DEFAULT 100,
	description TEXT,
	created_at TIMESTAMPTZ DEFAULT NOW(),
	updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS permissions (
	id VARCHAR(26) PRIMARY KEY,
	name VARCHAR(100) UNIQUE NOT NULL DEFAULT '',
	slug VARCHAR(100) UNIQUE,
	description TEXT,
	created_at TIMESTAMPTZ DEFAULT NOW()
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

-- OAuth
CREATE TABLE IF NOT EXISTS oauth_clients (
	id VARCHAR(26) PRIMARY KEY,
	client_id VARCHAR(100) UNIQUE NOT NULL,
	client_secret_hash TEXT NOT NULL,
	name VARCHAR(100) NOT NULL,
	redirect_uris JSONB NOT NULL,
	created_at TIMESTAMPTZ DEFAULT NOW(),
	updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_grants (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	client_id VARCHAR(26) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	scopes JSONB,
	created_at TIMESTAMPTZ DEFAULT NOW(),
	UNIQUE(user_id, client_id)
);

-- Audit and Infrastructure
CREATE TABLE IF NOT EXISTS audit_logs (
	id VARCHAR(26) PRIMARY KEY,
	user_id VARCHAR(26) REFERENCES users(id) ON DELETE SET NULL,
	action VARCHAR(100) NOT NULL,
	risk_level SMALLINT DEFAULT 1,
	ip_address INET,
	user_agent TEXT,
	device_id VARCHAR(26),
	metadata JSONB,
	created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_api_tokens (
  id VARCHAR(26) PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS secret_key_versions (
  id VARCHAR(26) PRIMARY KEY,
  family VARCHAR(32) NOT NULL CHECK (family IN ('access', 'refresh', 'one_time', 'admin_api')),
  version BIGINT NOT NULL CHECK (version > 0),
  state VARCHAR(16) NOT NULL CHECK (state IN ('active', 'previous')),
  secret_ciphertext TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (family, version),
  UNIQUE (family, state)
);
