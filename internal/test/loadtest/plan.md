# IAM Load Test Plan

## Goal

- Validate IAM behavior under `load`, `stress`, `spike`, and `soak` with route-level tags.
- Keep baseline numbers clean by isolating rate-limited auth routes into a dedicated lane.
- Measure refresh correctness after CAS change (single-use refresh token, no double-issue).

## Script and Scope

- Script: `internal/iam/test/loadtest/k6-iam.js`
- Core endpoints covered:
  - `POST /api/v1/auth/login` (rate-limited lane)
  - `POST /api/v1/auth/refresh` (rate-limited lane)
  - `POST /api/v1/auth/logout` (rate-limited lane)
  - `GET /api/v1/whoami` (baseline + auth lane)
  - `GET /api/v1/me/devices` (baseline + auth lane)
- Refresh proof contract in script: `jti + iat + htm + htu + token_hash + device_id + signature`.

## Scenario Matrix

- `PHASE=load`
  - `load_baseline`: `constant-vus`, default `100 VUs`, `5m`
  - `load_auth_limited`: `constant-vus`, default `1 VU`, `5m`
- `PHASE=stress`
  - `stress_baseline`: `ramping-vus` to `STRESS_MAX_VUS`
  - `stress_auth_limited`: `constant-vus`, `1 VU`
- `PHASE=spike`
  - `spike_baseline`: `ramping-vus` sudden jump to `SPIKE_VUS`
  - `spike_auth_limited`: `constant-vus`, `1 VU`
- `PHASE=soak`
  - `soak_baseline`: `constant-vus`, default `50 VUs`, `SOAK_DURATION`
  - `soak_auth_limited`: `constant-vus`, `1 VU`, same duration

## Environment Variables

- Required:
  - `BASE_URL` (example: `http://127.0.0.1:8080`)
  - `TEST_USERNAME`
  - `TEST_PASSWORD`
- Optional tuning:
  - `PHASE`, `LOAD_VUS`, `LOAD_DURATION`
  - `STRESS_START_VUS`, `STRESS_MAX_VUS`, `STRESS_STEP_DURATION`
  - `SPIKE_VUS`, `SPIKE_RAMP_UP`, `SPIKE_HOLD`, `SPIKE_RAMP_DOWN`
  - `SOAK_VUS`, `SOAK_DURATION`
  - `AUTH_LANE_VUS`, `AUTH_ITER_SLEEP_SEC`

## Run Commands

```bash
# load
PHASE=load BASE_URL=http://127.0.0.1:8080 TEST_USERNAME=iam.loadtest TEST_PASSWORD=Loadtest123! \
k6 run internal/iam/test/loadtest/k6-iam.js

# stress
PHASE=stress BASE_URL=http://127.0.0.1:8080 TEST_USERNAME=iam.loadtest TEST_PASSWORD=Loadtest123! \
k6 run internal/iam/test/loadtest/k6-iam.js

# spike
PHASE=spike BASE_URL=http://127.0.0.1:8080 TEST_USERNAME=iam.loadtest TEST_PASSWORD=Loadtest123! \
k6 run internal/iam/test/loadtest/k6-iam.js

# soak
PHASE=soak SOAK_DURATION=30m BASE_URL=http://127.0.0.1:8080 TEST_USERNAME=iam.loadtest TEST_PASSWORD=Loadtest123! \
k6 run internal/iam/test/loadtest/k6-iam.js
```

## Acceptance Targets

- `load (100 VU)`:
  - `GET /api/v1/whoami` p95 `< 100ms`
  - `POST /api/v1/auth/refresh` p95 `< 150ms` (auth_limited lane)
- `stress/spike`:
  - Identify explicit failure point (VU/rate, first degraded route, error pattern).
  - No duplicate successful refresh for same token under concurrent requests.
- `soak >= 30m`:
  - Memory trend stable (no monotonic leak pattern).
  - Unexpected error rate `< 0.5%` after excluding expected 429 from auth-limited checks.

## SQL Perf Verification

```sql
EXPLAIN (ANALYZE, BUFFERS)
SELECT
	u.id,
	u.username,
	u.email,
	COALESCE(u.phone, '') AS phone,
	u.security_level,
	u.status,
	COALESCE(p.fullname, '') AS fullname,
	COALESCE(p.avatar_url, '') AS avatar_url,
	COALESCE(p.bio, '') AS bio,
	COALESCE(
		ARRAY_AGG(DISTINCT r.name ORDER BY r.name)
		FILTER (WHERE r.name IS NOT NULL),
		ARRAY[]::text[]
	) AS role_names,
	COALESCE(
		ARRAY_AGG(
			DISTINCT COALESCE(NULLIF(perm.name, ''), NULLIF(perm.slug, ''))
			ORDER BY COALESCE(NULLIF(perm.name, ''), NULLIF(perm.slug, ''))
		)
		FILTER (WHERE COALESCE(NULLIF(perm.name, ''), NULLIF(perm.slug, '')) IS NOT NULL),
		ARRAY[]::text[]
	) AS permission_names
FROM iam.users u
JOIN iam.user_profiles p ON p.user_id = u.id
LEFT JOIN iam.user_roles ur ON ur.user_id = u.id
LEFT JOIN iam.roles r ON r.id = ur.role_id
LEFT JOIN iam.role_permissions rp ON rp.role_id = r.id
LEFT JOIN iam.permissions perm ON perm.id = rp.permission_id
WHERE u.id = 'bench-whoami-user'
GROUP BY u.id, u.username, u.email, u.phone, u.security_level, u.status, p.fullname, p.avatar_url, p.bio;

EXPLAIN (ANALYZE, BUFFERS)
WITH doomed AS (
	SELECT id
	FROM iam.refresh_tokens
	WHERE expires_at < NOW()
	ORDER BY expires_at ASC
	LIMIT 500
)
DELETE FROM iam.refresh_tokens t
USING doomed
WHERE t.id = doomed.id;
```
