# IAM Flow: RBAC Admin and Cache Coherency

## Endpoints

1. `GET /admin/rbac/roles`
2. `POST /admin/rbac/roles`
3. `GET /admin/rbac/roles/:id`
4. `PUT /admin/rbac/roles/:id`
5. `DELETE /admin/rbac/roles/:id`
6. `GET /admin/rbac/permissions`
7. `POST /admin/rbac/permissions`
8. `POST /admin/rbac/roles/:id/permissions`
9. `DELETE /admin/rbac/roles/:id/permissions/:perm_id`
10. `POST /admin/rbac/cache/invalidate`

## Middleware

- All endpoints: `AdminAPIToken()`

## Sequence Diagram: Mutation + Invalidation Broadcast

```mermaid
sequenceDiagram
    autonumber
    participant C as Admin Client
    participant T as AdminAPIToken
    participant H as RbacHandler
    participant S as RbacService
    participant R as RbacRepository
    participant PG as Postgres
    participant L as Local RoleRegistry
    participant B as RedisRbacCacheBus
    participant RS as Redis PubSub

    C->>T: RBAC mutation request
    T-->>H: pass
    H->>S: Create/Update/Delete/Assign/Revoke
    S->>R: write mutation
    R->>PG: INSERT/UPDATE/DELETE
    PG-->>R: success
    R-->>S: success
    S->>L: InvalidateRole or InvalidateAll
    S->>B: Publish invalidation event
    B->>RS: PUBLISH iam:rbac:invalidate + epoch increment
    H-->>C: 200/201
```

## Sequence Diagram: Multi-Replica Self-Heal

```mermaid
sequenceDiagram
    autonumber
    participant P1 as IAM Pod 1
    participant P2 as IAM Pod 2
    participant RS as Redis PubSub
    participant RK as Redis rbac:epoch
    participant L1 as Registry Pod1
    participant L2 as Registry Pod2

    P1->>RS: publish invalidate event (epoch++)
    RS-->>P2: message arrives
    P2->>L2: invalidate role/all
    Note over P2: if message missed
    P2->>RK: periodic epoch check (sync tick)
    alt epoch advanced
        P2->>L2: InvalidateAll (self-heal)
    else unchanged
        P2->>L2: keep cache
    end
```

## Notes

1. `RoleRegistry` remains fast-path cache, but not source of truth.
2. DB remains authoritative; Redis bus provides cross-replica coherence.
3. `InvalidateAll` triggers both local flush and distributed broadcast.
