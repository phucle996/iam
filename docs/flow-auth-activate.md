# IAM Flow: Activate Account

## Endpoint

- `GET /api/v1/auth/activate?token=...`
- Middleware: `RateLimit(auth_activate)`

## Purpose

- Consume activation token.
- Activate user and grant default role (`user`).

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RL as RateLimit
    participant H as AuthHandler.Activate
    participant S as AuthService.Activate
    participant R as Redis
    participant U as UserRepository
    participant PG as Postgres

    C->>RL: GET /api/v1/auth/activate?token=...
    RL->>H: pass
    H->>S: Activate(token)
    S->>R: HGETALL iam:ott:register:<token_digest>
    alt token missing/expired
        S-->>H: ErrActivationTokenExpired/Invalid
        H-->>C: 400
    else token valid
        S->>U: Activate(user_id)
        U->>PG: UPDATE iam.users status=active
        U->>PG: SELECT iam.roles where name='user'
        U->>PG: INSERT iam.user_roles ON CONFLICT DO NOTHING
        PG-->>U: commit
        U-->>S: success
        S->>R: DEL activation key
        S-->>H: success
        H-->>C: 200 account activated
    end
```

## Main Branches

1. Missing query token -> `400`.
2. Invalid or expired token -> `400`.
3. Activation role missing in DB -> internal error branch (`500`).
4. Success -> `200`.
