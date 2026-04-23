# IAM Flow: WhoAmI

## Endpoint

- `GET /api/v1/whoami`
- Middleware chain:
1. `Access()`
2. `RequireDeviceID()`

## Purpose

- Return authenticated session snapshot for UI bootstrap.
- Include identity, profile fields, roles, and permissions in one response.

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant A as Access middleware
    participant D as RequireDeviceID middleware
    participant H as AuthHandler.WhoAmI
    participant S as AuthService.WhoAmI
    participant U as UserRepository.GetWhoAmI
    participant PG as Postgres
    participant R as Redis

    C->>A: GET /api/v1/whoami
    A->>R: EXISTS blacklist key by jti
    A-->>D: claims in gin context (user_id, device_id,...)
    D->>D: compare cookie device_id vs claim device_id
    D-->>H: pass
    H->>S: WhoAmI(user_id)
    S->>U: GetWhoAmI(user_id)
    U->>PG: single aggregate query (ARRAY_AGG roles/perms)
    PG-->>U: flattened row
    U-->>S: entity.WhoAmI
    S-->>H: whoami data
    H-->>C: 200 {user/profile/roles/permissions}
```

## Main Branches

1. Missing/invalid access session -> middleware returns `401`.
2. User/profile/role not found at service boundary -> `401`.
3. Success -> `200`.

## Response Shape

- Returns one JSON object (`WhoamiResponse`) including:
1. identity fields (`user_id`, `username`, `email`, ...)
2. profile fields (`full_name`, `avatar_url`, `bio`, ...)
3. auth/session fields (`auth_type`, `level`, ...)
4. `roles[]`, `permissions[]`.
