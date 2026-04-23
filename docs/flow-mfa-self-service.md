# IAM Flow: MFA Self-Service Management

## Endpoints

1. `GET /api/v1/me/mfa`
2. `POST /api/v1/me/mfa/totp/enroll`
3. `POST /api/v1/me/mfa/totp/confirm`
4. `PATCH /api/v1/me/mfa/:setting_id/enable`
5. `PATCH /api/v1/me/mfa/:setting_id/disable`
6. `DELETE /api/v1/me/mfa/:setting_id`
7. `POST /api/v1/me/mfa/recovery-codes`

## Middleware

All routes require:

1. `Access()`
2. `RequireDeviceID()`
3. Route-specific `RateLimit(...)`

## Sequence Diagram: Enroll and Confirm TOTP

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant A as Access + RequireDeviceID
    participant H as MfaHandler
    participant S as MfaService
    participant U as UserRepository
    participant M as MfaRepository
    participant PG as Postgres

    C->>A: POST /api/v1/me/mfa/totp/enroll
    A-->>H: user_id in context
    H->>S: EnrollTOTP(user_id, device_name)
    S->>U: GetByID(user_id)
    U->>PG: SELECT user
    S->>S: generate secret + provisioning URI
    S->>M: Create(mfa_setting disabled)
    M->>PG: INSERT iam.mfa_settings
    H-->>C: 200 setting_id + provisioning_uri

    C->>A: POST /api/v1/me/mfa/totp/confirm
    A-->>H: user_id
    H->>S: ConfirmTOTP(user_id, setting_id, code)
    S->>M: GetByID(setting_id)
    M->>PG: SELECT mfa setting
    S->>S: validate TOTP code
    S->>M: UpdateEnabled(setting_id,true)
    M->>PG: UPDATE mfa setting
    H-->>C: 200 totp enabled
```

## Sequence Diagram: List, Toggle, Delete, Recovery Codes

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant A as Access + RequireDeviceID
    participant H as MfaHandler
    participant S as MfaService
    participant M as MfaRepository
    participant PG as Postgres

    C->>A: GET /api/v1/me/mfa
    A-->>H: user_id
    H->>S: ListMethods(user_id)
    S->>M: ListEnabled(user_id)
    M->>PG: SELECT settings
    H-->>C: 200 methods

    C->>A: PATCH/DELETE /api/v1/me/mfa/:setting_id...
    H->>S: Enable/Disable/Delete
    S->>M: owner check + update/delete
    M->>PG: SQL update/delete
    H-->>C: 200

    C->>A: POST /api/v1/me/mfa/recovery-codes
    H->>S: GenerateRecoveryCodes(user_id)
    S->>M: ReplaceRecoveryCodes(batch)
    M->>PG: replace codes transaction
    H-->>C: 200 codes shown once
```

## Notes

1. Recovery codes are only returned once and must be stored by client.
2. MFA challenge verify (`/auth/mfa/verify`) is documented separately in `flow-auth-mfa-verify.md`.
