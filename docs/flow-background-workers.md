# IAM Flow: Background Workers and Shutdown

## Purpose

- Keep runtime healthy in multi-instance deployment.
- Ensure worker lifecycle is tied to IAM module lifecycle.

## Components

1. RBAC cache sync worker (`RbacCacheSync`)
2. Token cleanup worker (`TokenService.CleanupExpired` in batches)
3. RoleRegistry TTL eviction (`registry.EvictExpired()`)

## Sequence Diagram: Module Startup

```mermaid
sequenceDiagram
    autonumber
    participant APP as App Bootstrap
    participant MOD as IAM Module
    participant RBAC as RbacService
    participant REG as RoleRegistry
    participant RS as RbacCacheSync
    participant TC as Cleanup Worker

    APP->>MOD: NewModule(cfg, infra, secrets)
    MOD->>RBAC: WarmUp()
    RBAC->>REG: preload role entries
    MOD->>RS: Start(context.Background())
    MOD->>TC: start ticker(5m)
    APP-->>MOD: module ready
```

## Sequence Diagram: Cleanup Tick

```mermaid
sequenceDiagram
    autonumber
    participant TC as Cleanup Worker
    participant REG as RoleRegistry
    participant TS as TokenService
    participant TR as TokenRepository
    participant PG as Postgres

    TC->>REG: EvictExpired()
    TC->>TS: CleanupExpired()
    loop up to cleanupMaxBatches
        TS->>TR: DeleteExpiredBatch(limit=500)
        TR->>PG: DELETE expired rows using CTE LIMIT
        PG-->>TR: rows affected
        TR-->>TS: deleted count
    end
    TS-->>TC: total deleted
```

## Sequence Diagram: Graceful Stop

```mermaid
sequenceDiagram
    autonumber
    participant APP as App.Stop
    participant MOD as IAM Module.Stop
    participant TC as Cleanup Worker
    participant RS as RbacCacheSync

    APP->>MOD: Stop()
    MOD->>TC: cancel cleanup context
    TC-->>MOD: cleanup goroutine exits
    MOD->>RS: Stop()
    RS-->>MOD: pubsub loop exits
    MOD-->>APP: stop complete (idempotent)
```

## Notes

1. Cleanup is idempotent and only touches expired refresh tokens.
2. Stop is designed to be safe for repeated calls.
3. Worker stop should run before infra shutdown so no worker uses closed DB/Redis.
