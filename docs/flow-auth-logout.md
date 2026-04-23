# IAM Flow: Logout

## Endpoint

- `POST /api/v1/auth/logout`
- Middleware chain:
1. `Access()`
2. `RequireDeviceID()`

## Purpose

- Invalidate current access token (`jti` blacklist).
- Revoke presented refresh token (best-effort).
- Clear all session cookies.

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant A as Access middleware
    participant D as RequireDeviceID middleware
    participant H as AuthHandler.Logout
    participant S as AuthService.Logout
    participant T as TokenService.RevokeByRaw
    participant TR as TokenRepository
    participant R as Redis
    participant PG as Postgres

    C->>A: POST /api/v1/auth/logout
    A->>A: parse JWT from Authorization or access_token cookie
    A->>R: EXISTS iam:blacklist:<jti>
    A-->>D: inject claims to gin context
    D->>D: compare cookie device_id vs JWT device_id
    D-->>H: pass

    H->>H: read jti from context, refresh_token cookie
    alt refresh cookie missing
        H-->>C: 401 unauthorized
    else present
        H->>S: Logout(jti, raw_refresh_token)
        S->>R: SET iam:blacklist:<jti> with access TTL
        S->>T: RevokeByRaw(raw_refresh_token)
        T->>TR: lookup by token hash + mark revoked
        TR->>PG: UPDATE refresh token revoked
        S-->>H: success (best-effort)
        H->>H: clear cookies access_token/refresh_token/device_id/refresh_token_hash
        H-->>C: 200 logged out successfully
    end
```

## Notes

1. Missing refresh cookie is treated as unauthorized.
2. Refresh revoke path is best-effort; cookie clearing still happens on success path.
