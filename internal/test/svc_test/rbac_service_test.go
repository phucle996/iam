package svc_test

import (
	"context"
	"errors"
	"testing"

	"iam/internal/domain/entity"
	"iam/internal/service"
	"iam/internal/transport/http/middleware"
	"iam/pkg/errorx"
)

type stubRbacRepo struct {
	listRoleEntriesCalls int
	listRolesCalls       int
	getRoleByNameCalls   int

	roleEntries []*entity.RoleWithPermissions
	roleByName  map[string]*entity.RoleWithPermissions
	roleByID    map[string]*entity.Role
}

func (r *stubRbacRepo) GetRoleByName(ctx context.Context, name string) (*entity.RoleWithPermissions, error) {
	r.getRoleByNameCalls++
	if r != nil && r.roleByName != nil {
		if role, ok := r.roleByName[name]; ok {
			return role, nil
		}
	}
	return nil, errorx.ErrRoleNotFound
}

func (r *stubRbacRepo) ListRoleEntries(ctx context.Context) ([]*entity.RoleWithPermissions, error) {
	r.listRoleEntriesCalls++
	return r.roleEntries, nil
}

func (r *stubRbacRepo) ListRoles(ctx context.Context) ([]*entity.Role, error) {
	r.listRolesCalls++
	var roles []*entity.Role
	for _, entry := range r.roleEntries {
		if entry != nil && entry.Role != nil {
			roles = append(roles, entry.Role)
		}
	}
	return roles, nil
}

func (r *stubRbacRepo) GetRoleByID(ctx context.Context, id string) (*entity.Role, error) {
	if r != nil && r.roleByID != nil {
		if role, ok := r.roleByID[id]; ok {
			return role, nil
		}
	}
	return nil, errorx.ErrRoleNotFound
}

func (r *stubRbacRepo) CreateRole(ctx context.Context, role *entity.Role) error { return nil }
func (r *stubRbacRepo) UpdateRole(ctx context.Context, role *entity.Role) error { return nil }
func (r *stubRbacRepo) DeleteRole(ctx context.Context, id string) error         { return nil }
func (r *stubRbacRepo) ListPermissions(ctx context.Context) ([]*entity.Permission, error) {
	return nil, nil
}
func (r *stubRbacRepo) GetPermissionByID(ctx context.Context, id string) (*entity.Permission, error) {
	return nil, errorx.ErrPermissionNotFound
}
func (r *stubRbacRepo) GetPermissionByName(ctx context.Context, name string) (*entity.Permission, error) {
	return nil, errorx.ErrPermissionNotFound
}
func (r *stubRbacRepo) CreatePermission(ctx context.Context, perm *entity.Permission) error {
	return nil
}
func (r *stubRbacRepo) AssignPermission(ctx context.Context, roleID, permissionID string) error {
	return nil
}
func (r *stubRbacRepo) RevokePermission(ctx context.Context, roleID, permissionID string) error {
	return nil
}

type stubRbacBus struct {
	rolePayload string
	allCount    int
}

func (b *stubRbacBus) PublishInvalidateRole(ctx context.Context, role string) error {
	b.rolePayload = role
	return nil
}

func (b *stubRbacBus) PublishInvalidateAll(ctx context.Context) error {
	b.allCount++
	return nil
}

func TestRbacServiceWarmUpUsesBulkRoleEntries(t *testing.T) {
	repo := &stubRbacRepo{
		roleEntries: []*entity.RoleWithPermissions{
			{
				Role:        &entity.Role{ID: "role-1", Name: "admin", Level: 0},
				Permissions: []string{"iam:users:read", "iam:users:write"},
			},
			{
				Role:        &entity.Role{ID: "role-2", Name: "viewer", Level: 10},
				Permissions: []string{"iam:users:read"},
			},
		},
	}
	registry := middleware.NewRoleRegistry()
	svc := service.NewRbacService(repo, registry, nil)

	if err := svc.WarmUp(context.Background()); err != nil {
		t.Fatalf("warm up: %v", err)
	}
	if repo.listRoleEntriesCalls != 1 {
		t.Fatalf("expected one bulk role query, got %d", repo.listRoleEntriesCalls)
	}
	if repo.getRoleByNameCalls != 0 {
		t.Fatalf("expected warm-up to avoid per-role lookups, got %d", repo.getRoleByNameCalls)
	}

	entry, ok := registry.Get("admin")
	if !ok {
		t.Fatalf("expected admin role to be cached")
	}
	if entry.Level != 0 || len(entry.Permissions) != 2 {
		t.Fatalf("unexpected cached admin entry: %+v", entry)
	}
}

func TestRbacServiceInvalidateRolePublishesAndClearsLocalCache(t *testing.T) {
	registry := middleware.NewRoleRegistry()
	registry.Set("admin", middleware.RoleEntry{Level: 0, Permissions: []string{"iam:users:read"}})
	bus := &stubRbacBus{}
	svc := service.NewRbacService(nil, registry, bus)

	svc.InvalidateRole(context.Background(), "admin")

	if _, ok := registry.Get("admin"); ok {
		t.Fatalf("expected admin cache entry to be cleared")
	}
	if bus.rolePayload != "admin" {
		t.Fatalf("expected invalidation payload to carry admin, got %q", bus.rolePayload)
	}
}

func TestRbacServiceInvalidateAllPublishesAndClearsLocalCache(t *testing.T) {
	registry := middleware.NewRoleRegistry()
	registry.Set("admin", middleware.RoleEntry{Level: 0})
	registry.Set("viewer", middleware.RoleEntry{Level: 10})
	bus := &stubRbacBus{}
	svc := service.NewRbacService(nil, registry, bus)

	svc.InvalidateAll(context.Background())

	if _, ok := registry.Get("admin"); ok {
		t.Fatalf("expected admin cache entry to be cleared")
	}
	if _, ok := registry.Get("viewer"); ok {
		t.Fatalf("expected viewer cache entry to be cleared")
	}
	if bus.allCount != 1 {
		t.Fatalf("expected full-flush publish, got %d", bus.allCount)
	}
}

func TestRbacServiceCreateRoleBroadcastsFullFlush(t *testing.T) {
	repo := &stubRbacRepo{}
	registry := middleware.NewRoleRegistry()
	registry.Set("admin", middleware.RoleEntry{Level: 0})
	bus := &stubRbacBus{}
	svc := service.NewRbacService(repo, registry, bus)

	if err := svc.CreateRole(context.Background(), &entity.Role{Name: "auditor"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if bus.allCount != 1 {
		t.Fatalf("expected create role to broadcast full flush, got %d", bus.allCount)
	}
}

func TestRbacServiceCreateRoleReturnsRepoError(t *testing.T) {
	expected := context.DeadlineExceeded
	svc := service.NewRbacService(&repoWithCreateErr{err: expected}, nil, nil)

	if err := svc.CreateRole(context.Background(), &entity.Role{Name: "auditor"}); !errors.Is(err, expected) {
		t.Fatalf("expected repo error, got %v", err)
	}
}

type repoWithCreateErr struct {
	err error
}

func (r *repoWithCreateErr) GetRoleByName(ctx context.Context, name string) (*entity.RoleWithPermissions, error) {
	return nil, errorx.ErrRoleNotFound
}
func (r *repoWithCreateErr) ListRoleEntries(ctx context.Context) ([]*entity.RoleWithPermissions, error) {
	return nil, nil
}
func (r *repoWithCreateErr) ListRoles(ctx context.Context) ([]*entity.Role, error) { return nil, nil }
func (r *repoWithCreateErr) GetRoleByID(ctx context.Context, id string) (*entity.Role, error) {
	return nil, errorx.ErrRoleNotFound
}
func (r *repoWithCreateErr) CreateRole(ctx context.Context, role *entity.Role) error { return r.err }
func (r *repoWithCreateErr) UpdateRole(ctx context.Context, role *entity.Role) error { return nil }
func (r *repoWithCreateErr) DeleteRole(ctx context.Context, id string) error         { return nil }
func (r *repoWithCreateErr) ListPermissions(ctx context.Context) ([]*entity.Permission, error) {
	return nil, nil
}
func (r *repoWithCreateErr) GetPermissionByID(ctx context.Context, id string) (*entity.Permission, error) {
	return nil, errorx.ErrPermissionNotFound
}
func (r *repoWithCreateErr) GetPermissionByName(ctx context.Context, name string) (*entity.Permission, error) {
	return nil, errorx.ErrPermissionNotFound
}
func (r *repoWithCreateErr) CreatePermission(ctx context.Context, perm *entity.Permission) error {
	return nil
}
func (r *repoWithCreateErr) AssignPermission(ctx context.Context, roleID, permissionID string) error {
	return nil
}
func (r *repoWithCreateErr) RevokePermission(ctx context.Context, roleID, permissionID string) error {
	return nil
}
