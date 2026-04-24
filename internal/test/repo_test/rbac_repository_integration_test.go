package repo_test

import (
	"context"
	"iam/internal/domain/entity"
	"iam/internal/repository"
	"iam/pkg/errorx"
	"errors"
	"testing"
	"time"
)

func TestRbacRepositoryCycle(t *testing.T) {
	db := mustOpenIAMRepositoryIntegrationDB(t)
	mustResetIAMState(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	repo := repository.NewRbacRepository(db)

	role := &entity.Role{
		ID:          "role-test-1",
		Name:        "test-role",
		Level:       50,
		Description: "A test role",
	}

	if err := repo.CreateRole(ctx, role); err != nil {
		t.Fatalf("create role: %v", err)
	}

	got, err := repo.GetRoleByName(ctx, "test-role")
	if err != nil {
		t.Fatalf("get role by name: %v", err)
	}
	if got.Role.ID != role.ID {
		t.Fatalf("expected ID %q, got %q", role.ID, got.Role.ID)
	}

	perm := &entity.Permission{
		ID:          "perm-test-1",
		Name:        "test:perm",
		Description: "A test permission",
	}
	if err := repo.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("create permission: %v", err)
	}

	if err := repo.AssignPermission(ctx, role.ID, perm.ID); err != nil {
		t.Fatalf("assign permission: %v", err)
	}

	gotWithPerm, _ := repo.GetRoleByName(ctx, "test-role")
	if len(gotWithPerm.Permissions) != 1 || gotWithPerm.Permissions[0] != "test:perm" {
		t.Fatalf("expected 1 permission, got %v", gotWithPerm.Permissions)
	}

	if err := repo.RevokePermission(ctx, role.ID, perm.ID); err != nil {
		t.Fatalf("revoke permission: %v", err)
	}

	gotRevoked, _ := repo.GetRoleByName(ctx, "test-role")
	if len(gotRevoked.Permissions) != 0 {
		t.Fatalf("expected 0 permissions after revoke, got %v", gotRevoked.Permissions)
	}

	if err := repo.DeleteRole(ctx, role.ID); err != nil {
		t.Fatalf("delete role: %v", err)
	}

	_, err = repo.GetRoleByID(ctx, role.ID)
	if !errors.Is(err, errorx.ErrRoleNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}
