# IAM Flow: MFA Verify (Challenge Completion)

## Endpoint

- `POST /api/v1/auth/mfa/verify`
- Middleware: `RateLimit(mfa_verify)`

## Purpose

- Complete login challenge after password authentication.
- On success, issue session cookies (same as direct login success).

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RL as RateLimit
    participant H as MfaHandler.Verify
    participant M as MfaService.Verify
    participant R as Redis
    participant MR as MfaRepository
    participant T as TokenService.IssueForMFA
    participant U as UserRepository
    participant D as DeviceRepository
    participant TR as TokenRepository
    participant PG as Postgres

    C->>RL: POST /api/v1/auth/mfa/verify
    RL->>H: pass
    H->>M: Verify(challenge_id, method, code)
    M->>R: HGETALL challenge
    M->>M: check expiry + allowed methods
    alt method = totp
        M->>MR: get setting/secret
        MR->>PG: SELECT setting
    else method = recovery
        M->>MR: consume recovery code
        MR->>PG: UPDATE recovery code used
    else method = sms/email
        M->>R: compare stored otp_code
    end

    alt verification failed
        M-->>H: mfa error
        H-->>C: 401/400 mapped error
    else verification success
        M->>R: DEL challenge (single-use)
        M-->>H: user_id, device_id
        H->>T: IssueForMFA(user_id, device_id)
        T->>U: GetByID
        U->>PG: SELECT user
        T->>D: GetDeviceByID
        D->>PG: SELECT device
        T->>TR: Create refresh token row
        TR->>PG: INSERT refresh token
        T-->>H: token pair
        H->>H: set session cookies
        H-->>C: 204 No Content
    end
```

## Main Branches

1. Invalid payload -> `400`.
2. Challenge invalid/not found/expired -> `401`.
3. MFA code invalid -> `401`.
4. Success -> `204`, cookies issued, no JSON token body.
