# IAM Flow: Refresh Token Rotation (DPoP-lite Proof)

## Endpoint

- `POST /api/v1/auth/refresh`
- Middleware: `RateLimit(auth_refresh)`

## Purpose

- Rotate refresh token using signed client proof.
- Prevent replay and double-consume race.

## Request Contract

1. Cookie: `refresh_token` (HttpOnly)
2. Cookie: `device_id` (readable)
3. JSON body: `jti`, `iat`, `htm`, `htu`, `token_hash`, `device_id`, `signature`

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RL as RateLimit
    participant H as TokenHandler.Refresh
    participant T as TokenService.Rotate
    participant TR as TokenRepository
    participant DR as DeviceRepository
    participant UR as UserRepository
    participant R as Redis
    participant PG as Postgres

    C->>RL: POST /api/v1/auth/refresh + proof
    RL->>H: pass
    H->>H: bind JSON proof
    H->>H: read refresh_token + device_id cookies
    H->>H: compare req.device_id == cookie device_id
    H->>T: Rotate(raw_refresh_token, proof)

    T->>T: validate required proof fields
    T->>TR: GetByHash(hash(raw token, secret candidates))
    TR->>PG: SELECT active refresh token
    T->>T: check stored.device_id == req.device_id
    T->>DR: GetDeviceByID
    DR->>PG: SELECT device public key + algorithm
    T->>T: verify htm/htu, token_hash, iat window, signature
    T->>R: SETNX iam:refresh:proof:<device_id>:<jti> TTL=proof_window
    alt replay detected
        R-->>T: already exists
        T-->>H: ErrRefreshSignatureReplay
        H-->>C: 401 generic
    else first use
        T->>TR: ConsumeActive(token_id)
        TR->>PG: UPDATE ... WHERE is_revoked=false AND expires_at>NOW()
        alt already consumed/expired
            TR-->>T: rows=0
            T-->>H: ErrRefreshTokenInvalid
            H-->>C: 401 generic
        else consumed
            T->>UR: GetByID(user_id)
            UR->>PG: SELECT user
            T->>DR: UpdateDevice(last_active_at) best-effort
            DR->>PG: UPDATE device
            T->>TR: Create(new refresh token hash)
            TR->>PG: INSERT refresh token
            T-->>H: new access+refresh pair
            H->>H: set session cookies
            H-->>C: 204 No Content
        end
    end
```

## Security Behavior

1. Missing refresh cookie or `device_id` cookie -> `401 unauthorized`.
2. All rotate failures (`invalid/mismatch/replay/unbound/signature`) -> generic `401`.
3. Successful refresh returns no token JSON body, only new cookies.
