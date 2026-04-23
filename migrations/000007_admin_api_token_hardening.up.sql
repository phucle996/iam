ALTER TABLE admin_api_tokens
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS is_bootstrap BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE admin_api_tokens
SET expires_at = COALESCE(expires_at, created_at + INTERVAL '15 minutes')
WHERE expires_at IS NULL;

ALTER TABLE admin_api_tokens
  ALTER COLUMN expires_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_admin_api_tokens_expires_at
  ON admin_api_tokens(expires_at);

CREATE INDEX IF NOT EXISTS idx_admin_api_tokens_is_bootstrap
  ON admin_api_tokens(is_bootstrap)
  WHERE is_bootstrap = TRUE;
