# IAM Flow: Device Management

## Endpoints

Self-service:

1. `GET /api/v1/me/devices`
2. `DELETE /api/v1/me/devices/:id`
3. `DELETE /api/v1/me/devices/others`

Admin:

1. `GET /admin/devices/:id`
2. `DELETE /admin/devices/:id`
3. `GET /admin/devices/:id/quarantine`
4. `POST /admin/devices/:id/suspicious`
5. `POST /admin/devices/cleanup`

## Middleware

Self-service routes:

1. `Access()`
2. `RequireDeviceID()`

Admin routes:

1. `AdminAPIToken()`

## Sequence Diagram: Self-Service List and Revoke

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant A as Access + RequireDeviceID
    participant H as DeviceHandler
    participant S as DeviceService
    participant R as DeviceRepository
    participant PG as Postgres

    C->>A: GET /api/v1/me/devices
    A-->>H: user_id + device_id in context
    H->>S: ListByUserID(user_id)
    S->>R: ListDevicesByUserID(user_id)
    R->>PG: SELECT devices
    PG-->>R: device rows
    R-->>S: devices
    S-->>H: devices
    H-->>C: 200 list devices

    C->>A: DELETE /api/v1/me/devices/:id
    A-->>H: user_id in context
    H->>S: Revoke(user_id, target_device_id)
    S->>R: GetDeviceByID(target_device_id)
    R->>PG: SELECT device
    S->>R: RevokeAllTokensByDevice(target_device_id)
    R->>PG: UPDATE refresh_tokens revoked
    S->>R: DeleteDevice(target_device_id)
    R->>PG: DELETE device
    H-->>C: 200 device revoked
```

## Sequence Diagram: Revoke Other Devices

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant A as Access + RequireDeviceID
    participant H as DeviceHandler.RevokeOtherDevices
    participant S as DeviceService
    participant R as DeviceRepository
    participant PG as Postgres

    C->>A: DELETE /api/v1/me/devices/others
    A-->>H: user_id + current device_id
    H->>S: RevokeOthers(user_id, keep_device_id)
    S->>R: RevokeOtherDevices(user_id, keep_device_id)
    R->>PG: revoke tokens + delete other devices
    PG-->>R: affected rows
    H-->>C: 200 {revoked: n}
```

## Sequence Diagram: Admin Device Operations

```mermaid
sequenceDiagram
    autonumber
    participant C as Admin Client
    participant T as AdminAPIToken middleware
    participant H as DeviceHandler.Admin*
    participant S as DeviceService
    participant R as DeviceRepository
    participant PG as Postgres

    C->>T: GET/DELETE/POST /admin/devices/...
    T-->>H: pass
    H->>S: admin device operation
    S->>R: read/update/delete
    R->>PG: SQL execution
    PG-->>R: result
    R-->>S: entity/result
    S-->>H: success/error
    H-->>C: mapped response
```

## Notes

1. Device binding identity is also enforced upstream on protected user routes via `RequireDeviceID`.
2. Device key bind/rebind logic is exercised mainly during login and explicit device security operations.
