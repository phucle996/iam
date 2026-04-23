package middleware

import (
	"sync"
	"time"
)

const defaultRoleTTL = 15 * time.Minute

// RoleEntry holds the resolved metadata for a role.
//
// Level semantics:
//
//	0  = highest privilege (e.g. super-admin)
//	N  = lower privilege the further from 0 (e.g. user = 4)
//
// RequireLevel(minLevel) passes when role.Level <= minLevel.
type RoleEntry struct {
	Level       int
	Permissions []string // flat list, e.g. ["iam:read", "iam:write"]
	// permissionLookup is precomputed once at cache-set time to keep hot-path checks O(1).
	permissionLookup map[string]struct{}
}

// cachedRoleEntry wraps RoleEntry with an expiry timestamp.
type cachedRoleEntry struct {
	entry     RoleEntry
	expiresAt time.Time
}

func (c *cachedRoleEntry) valid() bool {
	return time.Now().Before(c.expiresAt)
}

// RoleRegistry is a thread-safe, TTL-aware in-memory cache of
// role name → RoleEntry. The RBAC service populates it via Set/SetWithTTL;
// authz middleware reads from it.
//
// Cache-miss policy: Get returns (_, false) when the entry is absent or
// expired, allowing the caller (RBAC service) to fall back to the database
// and re-populate the cache.
type RoleRegistry struct {
	mu    sync.RWMutex
	roles map[string]*cachedRoleEntry
	ttl   time.Duration
}

// NewRoleRegistry creates an empty registry with the default 15-minute TTL.
func NewRoleRegistry() *RoleRegistry {
	return &RoleRegistry{
		roles: make(map[string]*cachedRoleEntry),
		ttl:   defaultRoleTTL,
	}
}

// Set caches a RoleEntry using the default TTL.
func (r *RoleRegistry) Set(role string, entry RoleEntry) {
	r.SetWithTTL(role, entry, r.ttl)
}

// SetWithTTL caches a RoleEntry with an explicit TTL.
func (r *RoleRegistry) SetWithTTL(role string, entry RoleEntry, ttl time.Duration) {
	entry = normalizeRoleEntry(entry)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role] = &cachedRoleEntry{
		entry:     entry,
		expiresAt: time.Now().Add(ttl),
	}
}

// Get returns the cached RoleEntry for a role.
// Returns (entry, true) only if the entry exists and has not expired.
func (r *RoleRegistry) Get(role string) (RoleEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.roles[role]
	if !ok || !c.valid() {
		return RoleEntry{}, false
	}
	return c.entry, true
}

// Invalidate removes a single role from the cache.
// The next request for this role will fall back to the database.
func (r *RoleRegistry) Invalidate(role string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.roles, role)
}

// InvalidateAll clears the entire cache.
func (r *RoleRegistry) InvalidateAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles = make(map[string]*cachedRoleEntry)
}

// EvictExpired removes all expired entries (call periodically to avoid leaks).
func (r *RoleRegistry) EvictExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for role, c := range r.roles {
		if now.After(c.expiresAt) {
			delete(r.roles, role)
		}
	}
}

func normalizeRoleEntry(entry RoleEntry) RoleEntry {
	if len(entry.Permissions) == 0 {
		entry.Permissions = []string{}
		entry.permissionLookup = map[string]struct{}{}
		return entry
	}

	lookup := make(map[string]struct{}, len(entry.Permissions))
	for _, permission := range entry.Permissions {
		lookup[permission] = struct{}{}
	}
	entry.permissionLookup = lookup
	return entry
}
