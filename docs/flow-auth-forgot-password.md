# IAM Flow: Forgot Password

## Endpoint

- `POST /api/v1/auth/forgot-password`
- Middleware: `RateLimit(auth_forgot_password)`

## Purpose

- Start reset-password flow without account enumeration.
- Always return accepted response to client.

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RL as RateLimit
    participant H as AuthHandler.ForgotPassword
    participant S as AuthService.ForgotPassword
    participant U as UserRepository
    participant R as Redis
    participant M as Mail Stream
    participant PG as Postgres

    C->>RL: POST /api/v1/auth/forgot-password
    RL->>H: pass
    H->>S: ForgotPassword(email)
    S->>U: GetByEmail(email)
    U->>PG: SELECT user by email

    alt user not found
        S-->>H: nil (silent success)
        H-->>C: 202 if email exists, link sent
    else user found
        S->>U: GetProfileByUserID
        U->>PG: SELECT profile
        S->>R: HSET+EXPIRE iam:ott:reset:<digest>
        S->>M: XADD stream:mail:outgoing (reset_password)
        S-->>H: success
        H-->>C: 202 if email exists, link sent
    end
```

## Security Notes

1. Client message is identical for existing and non-existing accounts.
2. Reset token is one-time metadata in Redis with TTL.
3. Internal errors are logged, not exposed in response details.
