# IAM Flow: Register

## Endpoint

- `POST /api/v1/auth/register`
- Middleware: `RateLimit(auth_register)`

## Purpose

- Create a pending account (`status=pending`) and enqueue activation email.
- Do not issue tokens at this step.

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RL as RateLimit
    participant H as AuthHandler.Register
    participant S as AuthService.Register
    participant U as UserRepository
    participant PG as Postgres
    participant R as Redis
    participant M as Mail Stream

    C->>RL: POST /api/v1/auth/register (payload)
    RL->>H: pass
    H->>H: validate payload and normalize
    H->>S: Register(user, profile, password)
    S->>R: bitmap precheck username/email (optional fast path)
    S->>U: CreatePendingAccount(...)
    U->>PG: INSERT iam.users + iam.user_profiles (transaction)
    PG-->>U: commit
    U-->>S: success
    S->>R: set bitmap username/email
    S->>R: HSET+EXPIRE activation token metadata
    S->>M: XADD stream:mail:outgoing (verify_email)
    S-->>H: success
    H-->>C: 201 Created (activation required)
```

## Main Branches

1. Invalid payload or weak password -> `400`.
2. Duplicate identity (`username/email/phone`) -> `409`.
3. Success -> `201` and account remains pending until activation.

## Security Notes

1. Password is hashed before persistence.
2. Activation token is one-time, stored in Redis with TTL.
3. No session cookies are issued in this flow.
