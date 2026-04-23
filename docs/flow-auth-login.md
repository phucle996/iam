# IAM Flow: Login

## Endpoint

- `POST /api/v1/auth/login`
- Middleware: `RateLimit(auth_login)`

## Purpose

- Authenticate username/password.
- Enforce device binding at login (`device_fingerprint`, `device_public_key`).
- Branch to pending activation, MFA challenge, or direct session issuance.

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RL as RateLimit
    participant H as AuthHandler.Login
    participant A as AuthService.Login
    participant U as UserRepository
    participant D as DeviceService.ResolveDevice
    participant DR as DeviceRepository
    participant M as MfaService.CheckAndChallenge
    participant T as TokenService.IssueAfterLogin
    participant TR as TokenRepository
    participant PG as Postgres
    participant R as Redis

    C->>RL: POST /api/v1/auth/login
    RL->>H: pass
    H->>H: validate payload + require device fields
    H->>A: Login(username,password,fingerprint,pubkey,alg)
    A->>U: GetByUsername
    U->>PG: SELECT user
    PG-->>U: user row
    U-->>A: user
    A->>A: verify password hash

    alt status = pending
        A->>U: GetProfileByUserID
        A->>R: store activation token + enqueue mail
        A-->>H: LoginResult{Pending=true}
        H-->>C: 202 pending activation
    else status != active
        A-->>H: ErrUserInactive
        H-->>C: 403
    else active
        A->>D: ResolveDevice(...)
        D->>DR: GetDeviceByFingerprint
        DR->>PG: SELECT device by (user_id,fingerprint)
        alt not found
            D->>DR: CreateDevice
            DR->>PG: INSERT device
        else found
            D->>DR: UpdateDevice(last_active, bind key only if empty)
            DR->>PG: UPDATE device
        end

        A->>M: CheckAndChallenge(user_id,device_id)
        alt MFA required
            M->>R: HSET+EXPIRE iam:mfa:challenge:<id>
            A-->>H: LoginResult{MFARequired=true,...}
            H-->>C: 202 + challenge_id + methods
        else no MFA
            A->>T: IssueAfterLogin(user,device)
            T->>TR: Create(refresh token hash)
            TR->>PG: INSERT iam.refresh_tokens
            T-->>A: access+refresh tokens
            A-->>H: LoginResult(tokens)
            H->>H: set cookies (access_token, refresh_token, device_id, refresh_token_hash)
            H-->>C: 204 No Content
        end
    end
```

## Response Branches

1. Bad payload or missing device fields -> `400`.
2. Invalid credentials -> `401`.
3. Inactive user -> `403`.
4. Pending account -> `202` (activation email resent).
5. MFA required -> `202` with `challenge_id`.
6. Login success -> `204` and cookies set, no token JSON body.

## Cookie Contract on Success

1. `access_token` (HttpOnly)
2. `refresh_token` (HttpOnly)
3. `device_id` (readable cookie for browser proof flow)
4. `refresh_token_hash` (readable cookie, helper hash only)
