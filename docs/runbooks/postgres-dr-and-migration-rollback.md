# Postgres DR And Migration Rollback

## 1. Backup drill (full)

```bash
export DB_URL='postgres://aurora:***@127.0.0.1:5432/aurora_iam?sslmode=disable'
export BACKUP_FILE="/var/backups/aurora-iam/aurora_iam_$(date +%Y%m%d_%H%M%S).dump"

pg_dump --format=custom --no-owner --no-privileges --dbname "$DB_URL" --file "$BACKUP_FILE"
```

Validation:

```bash
pg_restore --list "$BACKUP_FILE" | head
```

## 2. Restore drill (staging target)

```bash
export RESTORE_DB_URL='postgres://aurora:***@127.0.0.1:5432/aurora_iam_restore?sslmode=disable'

createdb aurora_iam_restore || true
pg_restore --clean --if-exists --no-owner --no-privileges --dbname "$RESTORE_DB_URL" "$BACKUP_FILE"
```

Post-restore checks:

```bash
psql "$RESTORE_DB_URL" -c "SELECT count(*) FROM users;"
psql "$RESTORE_DB_URL" -c "SELECT count(*) FROM secret_key_versions;"
```

## 3. Migration rollback gate

Before applying any down migration in production:

1. Confirm fresh backup exists and restore has been tested.
2. Put write traffic in maintenance mode.
3. Roll back only the target migration file.

Example (rollback `000007_admin_api_token_hardening`):

```bash
psql "$DB_URL" -v ON_ERROR_STOP=1 -f migrations/000007_admin_api_token_hardening.down.sql
```

After rollback:

```bash
psql "$DB_URL" -c "\d+ admin_api_tokens"
```

## 4. Secret key rollback (active <- previous)

If a new secret version causes verification failures, promote previous key as active for the impacted family.

```sql
BEGIN;

UPDATE secret_key_versions
SET state = 'previous', expires_at = NOW() + INTERVAL '24 hours', updated_at = NOW()
WHERE family = 'access' AND state = 'active';

UPDATE secret_key_versions
SET state = 'active', expires_at = NOW() + INTERVAL '10 years', rotated_at = NOW(), updated_at = NOW()
WHERE family = 'access' AND version = <PREVIOUS_VERSION> AND state = 'previous';

COMMIT;
```

Repeat for `refresh`, `one_time`, `admin_api` as needed.

## 5. Recovery completion checklist

- API health endpoints are `200`.
- Login + refresh pass smoke test.
- No active `IAMHTTP5xxRateHigh` alert.
- No spike on `IAMRefreshReplaySpike` after recovery window.
