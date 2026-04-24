package repo_test

import (
	"context"
	"iam/internal/domain/entity"
	"iam/internal/repository"
	"testing"
	"time"
)

func TestAdminAPITokenRepositoryCycle(t *testing.T) {
	db := mustOpenIAMRepositoryIntegrationDB(t)
	mustResetIAMState(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	repo := repository.NewAdminAPITokenRepository(db)

	hasAny, err := repo.HasAdminAPITokens(ctx)
	if err != nil {
		t.Fatalf("has any: %v", err)
	}
	if hasAny {
		t.Fatalf("expected no tokens in fresh state")
	}

	token := &entity.AdminAPIToken{
		ID:        "admin-rt-1",
		TokenHash: "admin-hash-1",
		CreatedAt: time.Now().UTC(),
	}

	if err := repo.CreateAdminAPIToken(ctx, token); err != nil {
		t.Fatalf("create admin token: %v", err)
	}

	hasAnyNow, _ := repo.HasAdminAPITokens(ctx)
	if !hasAnyNow {
		t.Fatalf("expected tokens to exist")
	}

	exists, err := repo.ExistsAdminAPITokenHash(ctx, "admin-hash-1")
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !exists {
		t.Fatalf("expected token hash to exist")
	}

	existsMissing, _ := repo.ExistsAdminAPITokenHash(ctx, "missing-hash")
	if existsMissing {
		t.Fatalf("expected missing hash not to exist")
	}
}
