# IAM Load Test Result

Date: `2026-04-22`  
Module: `internal/iam`  
Script: `internal/iam/test/loadtest/k6-iam.js`

## 1) Environment

- App commit/tag: `local workspace`
- Base URL: `http://127.0.0.1:8080` (verification run)
- DB: `not reset in this verification run`
- Redis: `not reset in this verification run`
- Test principal: `iam.loadtest` (verification run failed: `401` on login)
- Device binding mode: `cookie + DPoP-lite refresh proof`

### Implementation Verification Status

- `go test ./internal/iam/...`: `PASS`
- `go test ./internal/http/middleware ./internal/iam/transport/http/handler ./internal/iam/service`: `PASS`
- `k6 archive internal/iam/test/loadtest/k6-iam.js`: `PASS`
- Short k6 execution (`PHASE=load`, `1 VU`, `10s`) reached runtime and failed at setup login (`401`), so full matrix is blocked until fixture user/password is valid in runtime env.

## 2) Run Matrix

| Phase | Command | Notes |
| --- | --- | --- |
| load | `PHASE=load ... k6 run .../k6-iam.js` | baseline + auth_limited |
| stress | `PHASE=stress ... k6 run .../k6-iam.js` | ramp to failure point |
| spike | `PHASE=spike ... k6 run .../k6-iam.js` | burst behavior |
| soak | `PHASE=soak SOAK_DURATION=30m ...` | memory drift check |

## 3) Metrics by Phase

| Phase | Requests | Req/s | Error % | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| load | 1 | 167.29 | 100.00 | 4.33 | 4.33 | 4.33 | 4.33 |
| stress | blocked | blocked | blocked | blocked | blocked | blocked | blocked |
| spike | blocked | blocked | blocked | blocked | blocked | blocked | blocked |
| soak | blocked | blocked | blocked | blocked | blocked | blocked | blocked |

## 4) Route-Level Breakdown

### Baseline Lane

| Route | p95 (ms) | Error % | Notes |
| --- | ---: | ---: | --- |
| `GET /api/v1/whoami` | blocked | blocked | blocked |
| `GET /api/v1/me/devices` | blocked | blocked | blocked |

### Auth-Limited Lane

| Route | p95 (ms) | Error % | Expected 429? | Notes |
| --- | ---: | ---: | --- | --- |
| `POST /api/v1/auth/login` | 4.33 | 100.00 | yes | setup login got `401` |
| `POST /api/v1/auth/refresh` | blocked | blocked | yes | setup blocked before refresh |
| `POST /api/v1/auth/logout` | blocked | blocked | no | setup blocked before logout |

## 5) Security/Correctness Checks

- Refresh race (same refresh token, concurrent calls): `PASS` (service/unit concurrency test)
- Unauthorized responses are generic (no internal-state leakage): `PASS` (handler tests)
- Device-bound refresh proof verification: `PASS` (service tests + k6 payload implementation)

## 6) Soak Memory / CPU Trend

| Timestamp | RSS (MB) | CPU (%) | Notes |
| --- | ---: | ---: | --- |
| t0 | blocked | blocked | blocked |
| t+10m | blocked | blocked | blocked |
| t+20m | blocked | blocked | blocked |
| t+30m | blocked | blocked | blocked |

## 7) Before vs After (Compared to Previous IAM Baseline)

| Metric | Previous | Current | Delta |
| --- | ---: | ---: | ---: |
| `whoami p95` | n/a | blocked | blocked |
| `refresh p95` | n/a | blocked | blocked |
| overall error rate | n/a | blocked | blocked |
| failure point (stress) | n/a | blocked | blocked |

## 8) Bottlenecks and Next Actions

1. Seed/activate test principal `iam.loadtest` with valid password in runtime DB.
2. Re-run full phase matrix (`load/stress/spike/soak`) and fill route-level section from k6 output.
3. Capture host memory/CPU samples during soak to complete production trend analysis.
