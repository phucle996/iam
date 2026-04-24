package repo_test

import (
	"context"
	"iam/internal/repository"
	"iam/pkg/errorx"
	"errors"
	"testing"
	"time"
)

func TestUserRepositoryGetWhoAmIAggregatesSessionGraph(t *testing.T) {
	db := mustOpenIAMRepositoryIntegrationDB(t)
	mustResetIAMState(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	userID := "whoami-user-1"
	roleAdminID := "role-admin"
	roleViewerID := "role-viewer"
	permReadID := "perm-read"
	permWriteID := "perm-write"

	mustExecIAM(t, db, `INSERT INTO users (id, username, email, phone, password_hash, security_level, status, status_reason, created_at, updated_at)
		VALUES ($1, 'whoami-user', 'whoami@example.com', NULL, 'hash', 2, 'active', '', NOW(), NOW())`, userID)
	mustExecIAM(t, db, `INSERT INTO user_profiles (id, user_id, fullname, avatar_url, bio, timezone, created_at, updated_at)
		VALUES ('profile-whoami', $1, 'Who Am I', 'https://cdn.example.com/avatar.png', 'hello', 'UTC', NOW(), NOW())`, userID)

	mustExecIAM(t, db, `INSERT INTO roles (id, name, level, description, created_at, updated_at)
		VALUES ($1, 'admin', 0, 'Administrator', NOW(), NOW())`, roleAdminID)
	mustExecIAM(t, db, `INSERT INTO roles (id, name, level, description, created_at, updated_at)
		VALUES ($1, 'viewer', 10, 'Viewer', NOW(), NOW())`, roleViewerID)

	mustExecIAM(t, db, `INSERT INTO permissions (id, name, description, created_at)
		VALUES ($1, 'iam:users:read', 'Read users', NOW())`, permReadID)
	mustExecIAM(t, db, `INSERT INTO permissions (id, name, description, created_at)
		VALUES ($1, 'iam:users:write', 'Write users', NOW())`, permWriteID)

	mustExecIAM(t, db, `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, userID, roleViewerID)
	mustExecIAM(t, db, `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, userID, roleAdminID)
	mustExecIAM(t, db, `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleAdminID, permReadID)
	mustExecIAM(t, db, `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleAdminID, permWriteID)
	mustExecIAM(t, db, `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleViewerID, permReadID)

	repo := repository.NewUserRepository(db)
	result, err := repo.GetWhoAmI(ctx, userID)
	if err != nil {
		t.Fatalf("get whoami result: %v", err)
	}

	if result == nil {
		t.Fatalf("expected whoami result, got %#v", result)
	}
	if result.UserID != userID {
		t.Fatalf("expected user id %q, got %q", userID, result.UserID)
	}
	if result.FullName != "Who Am I" {
		t.Fatalf("expected full name, got %q", result.FullName)
	}

	wantRoles := []string{"admin", "viewer"}
	if len(result.Roles) != len(wantRoles) {
		t.Fatalf("expected %d roles, got %#v", len(wantRoles), result.Roles)
	}
	for i, want := range wantRoles {
		if result.Roles[i] != want {
			t.Fatalf("expected role %d to be %q, got %q", i, want, result.Roles[i])
		}
	}

	wantPerms := []string{"iam:users:read", "iam:users:write"}
	if len(result.Permissions) != len(wantPerms) {
		t.Fatalf("expected %d permissions, got %#v", len(wantPerms), result.Permissions)
	}
	for i, want := range wantPerms {
		if result.Permissions[i] != want {
			t.Fatalf("expected permission %d to be %q, got %q", i, want, result.Permissions[i])
		}
	}

}

func TestUserRepositoryGetWhoAmIReturnsNotFoundForMissingUser(t *testing.T) {
	db := mustOpenIAMRepositoryIntegrationDB(t)
	mustResetIAMState(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	repo := repository.NewUserRepository(db)
	result, err := repo.GetWhoAmI(ctx, "missing-user")
	if !errors.Is(err, errorx.ErrUserNotFound) {
		t.Fatalf("expected user not found, got result=%#v err=%v", result, err)
	}
	if result != nil {
		t.Fatalf("expected nil result for missing user, got %#v", result)
	}
}

func TestUserRepositoryUpdatePasswordStoresPreviousHashHistory(t *testing.T) {
	db := mustOpenIAMRepositoryIntegrationDB(t)
	mustResetIAMState(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	userID := "password-user-1"
	mustExecIAM(t, db, `INSERT INTO users (id, username, email, phone, password_hash, security_level, status, status_reason, created_at, updated_at)
		VALUES ($1, 'password-user', 'password-user@example.com', NULL, 'old-hash', 2, 'active', '', NOW(), NOW())`, userID)

	repo := repository.NewUserRepository(db)
	if err := repo.UpdatePassword(ctx, userID, "new-hash"); err != nil {
		t.Fatalf("update password: %v", err)
	}

	var currentHash string
	mustQueryRowIAM(t, db, `SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&currentHash)
	if currentHash != "new-hash" {
		t.Fatalf("expected current password hash to be updated, got %q", currentHash)
	}

	var historyHash string
	mustQueryRowIAM(t, db, `SELECT password_hash FROM password_histories WHERE user_id = $1`, userID).Scan(&historyHash)
	if historyHash != "old-hash" {
		t.Fatalf("expected previous password hash in history, got %q", historyHash)
	}
}
