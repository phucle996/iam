DROP INDEX IF EXISTS idx_admin_api_tokens_is_bootstrap;
DROP INDEX IF EXISTS idx_admin_api_tokens_expires_at;

ALTER TABLE admin_api_tokens
  DROP COLUMN IF EXISTS is_bootstrap,
  DROP COLUMN IF EXISTS expires_at;
