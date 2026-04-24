package service

import (
	"context"
	"iam/internal/domain/entity"
	domainrepo "iam/internal/domain/repository"
	"iam/internal/transport/http/middleware"
	"fmt"
)

// RbacService implements iam_domainsvc.RbacService.
//
// Cache-aside: every GetRoleEntry checks RoleRegistry first; on miss it fetches
// from Postgres, populates the registry (15-min TTL by default), then returns.
// Every mutation that changes a role's name/level/permissions calls
// InvalidateRole so the next request sees fresh data.
type RbacService struct {
	repo     domainrepo.RbacRepository
	registry *middleware.RoleRegistry
	bus      RbacCacheBus
}

func NewRbacService(repo domainrepo.RbacRepository, registry *middleware.RoleRegistry, bus RbacCacheBus) *RbacService {
	return &RbacService{repo: repo, registry: registry, bus: bus}
}

// ── RoleResolver ──────────────────────────────────────────────────────────────

// LoadRole fetches role metadata from DB, used by middleware.GetRoleEntry on cache miss.
func (s *RbacService) LoadRole(ctx context.Context, role string) (middleware.RoleEntry, error) {
	rp, err := s.repo.GetRoleByName(ctx, role)
	if err != nil {
		return middleware.RoleEntry{}, fmt.Errorf("rbac svc: load %q: %w", role, err)
	}

	return middleware.RoleEntry{
		Level:       rp.Role.Level,
		Permissions: rp.Permissions,
	}, nil
}

// InvalidateRole evicts one role so the next request refetches.
func (s *RbacService) InvalidateRole(ctx context.Context, role string) {
	if s.registry != nil {
		s.registry.Invalidate(role)
	}
	if s.bus != nil {
		_ = s.bus.PublishInvalidateRole(ctx, role)
	}
}

// InvalidateAll clears the entire cache.
func (s *RbacService) InvalidateAll(ctx context.Context) {
	if s.registry != nil {
		s.registry.InvalidateAll()
	}
	if s.bus != nil {
		_ = s.bus.PublishInvalidateAll(ctx)
	}
}

// WarmUp preloads all roles at startup to avoid cold cache on first requests.
func (s *RbacService) WarmUp(ctx context.Context) error {
	roles, err := s.repo.ListRoleEntries(ctx)
	if err != nil {
		return fmt.Errorf("rbac svc: warm-up: %w", err)
	}
	for _, roleEntry := range roles {
		if roleEntry == nil || roleEntry.Role == nil {
			continue
		}
		s.registry.Set(roleEntry.Role.Name, middleware.RoleEntry{
			Level:       roleEntry.Role.Level,
			Permissions: roleEntry.Permissions,
		})
	}
	return nil
}

// ── Role admin ────────────────────────────────────────────────────────────────

func (s *RbacService) ListRoles(ctx context.Context) ([]*entity.Role, error) {
	return s.repo.ListRoles(ctx)
}

func (s *RbacService) GetRole(ctx context.Context, id string) (*entity.RoleWithPermissions, error) {
	role, err := s.repo.GetRoleByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetRoleByName(ctx, role.Name)
}

func (s *RbacService) CreateRole(ctx context.Context, role *entity.Role) error {
	if err := s.repo.CreateRole(ctx, role); err != nil {
		return err
	}
	s.InvalidateAll(ctx)
	return nil
}

// UpdateRole persists changes and invalidates the old + new role name from cache.
func (s *RbacService) UpdateRole(ctx context.Context, role *entity.Role) error {
	old, err := s.repo.GetRoleByID(ctx, role.ID)
	if err != nil {
		return err
	}
	if err := s.repo.UpdateRole(ctx, role); err != nil {
		return err
	}
	s.InvalidateRole(ctx, old.Name)
	if role.Name != old.Name {
		s.InvalidateRole(ctx, role.Name)
	}
	return nil
}

// DeleteRole removes the role from DB and evicts it from cache.
func (s *RbacService) DeleteRole(ctx context.Context, id string) error {
	role, err := s.repo.GetRoleByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.repo.DeleteRole(ctx, id); err != nil {
		return err
	}
	s.InvalidateRole(ctx, role.Name)
	return nil
}

// ── Permission admin ──────────────────────────────────────────────────────────

func (s *RbacService) ListPermissions(ctx context.Context) ([]*entity.Permission, error) {
	return s.repo.ListPermissions(ctx)
}

func (s *RbacService) CreatePermission(ctx context.Context, perm *entity.Permission) error {
	return s.repo.CreatePermission(ctx, perm)
}

// AssignPermission adds a permission and invalidates the affected role's cache.
func (s *RbacService) AssignPermission(ctx context.Context, roleID, permID string) error {
	if err := s.repo.AssignPermission(ctx, roleID, permID); err != nil {
		return err
	}
	if role, err := s.repo.GetRoleByID(ctx, roleID); err == nil {
		s.InvalidateRole(ctx, role.Name)
	}
	return nil
}

// RevokePermission removes a permission and invalidates the affected role's cache.
func (s *RbacService) RevokePermission(ctx context.Context, roleID, permID string) error {
	if err := s.repo.RevokePermission(ctx, roleID, permID); err != nil {
		return err
	}
	if role, err := s.repo.GetRoleByID(ctx, roleID); err == nil {
		s.InvalidateRole(ctx, role.Name)
	}
	return nil
}
