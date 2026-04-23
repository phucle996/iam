# IAM Flow: Reset Password

## Endpoint

- `POST /api/v1/auth/reset-password?token=...`
- Middleware: `RateLimit(auth_reset_password)`

## Purpose

- Validate one-time reset token.
- Update password hash.
- Revoke all user refresh tokens.

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RL as RateLimit
    participant H as AuthHandler.ResetPassword
    participant S as AuthService.ResetPassword
    participant R as Redis
    participant U as UserRepository
    participant T as TokenService
    participant TR as TokenRepository
    participant PG as Postgres

    C->>RL: POST /api/v1/auth/reset-password?token=...
    RL->>H: pass
    H->>H: validate payload + password confirmation
    H->>S: ResetPassword(token, new_password)
    S->>R: HGETALL iam:ott:reset:<token_digest>
    alt token missing/expired
        S-->>H: ErrResetTokenExpired/Invalid
        H-->>C: 400
    else token valid
        S->>S: validate expires_at and hash new password
        S->>U: UpdatePassword(user_id, hash)
        U->>PG: UPDATE iam.users password_hash
        S->>T: RevokeAllByUser(user_id)
        T->>TR: RevokeAllByUser(user_id)
        TR->>PG: UPDATE iam.refresh_tokens SET is_revoked=true
        S->>R: DEL reset token key
        S-->>H: success
        H-->>C: 200 password reset successful
    end
```

## Main Branches

1. Invalid payload / mismatched password confirmation -> `400`.
2. Invalid or expired reset token -> `400`.
3. Success -> `200`.
