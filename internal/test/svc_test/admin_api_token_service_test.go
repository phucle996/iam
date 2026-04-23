package svc_test

import (
	"context"
	"testing"
	"time"

	"controlplane/internal/config"
	"controlplane/internal/domain/entity"
	"controlplane/internal/security"
	"controlplane/internal/service"
)

type adminAPITokenRepoStub struct {
	hasAny    bool
	tokens    map[string]*entity.AdminAPIToken
	existsHit int
}

func (r *adminAPITokenRepoStub) HasAdminAPITokens(ctx context.Context) (bool, error) {
	if r.hasAny {
		return true, nil
	}
	now := time.Now().UTC()
	for _, token := range r.tokens {
		if token != nil && token.ExpiresAt.After(now) {
			return true, nil
		}
	}
	return false, nil
}

func (r *adminAPITokenRepoStub) CreateAdminAPIToken(ctx context.Context, token *entity.AdminAPIToken) error {
	if r.tokens == nil {
		r.tokens = make(map[string]*entity.AdminAPIToken)
	}
	cp := *token
	r.tokens[token.TokenHash] = &cp
	return nil
}

func (r *adminAPITokenRepoStub) ExistsAdminAPITokenHash(ctx context.Context, tokenHash string) (bool, error) {
	r.existsHit++
	_, ok := r.tokens[tokenHash]
	return ok, nil
}

func (r *adminAPITokenRepoStub) GetActiveByHash(ctx context.Context, tokenHash string) (*entity.AdminAPIToken, error) {
	r.existsHit++
	token, ok := r.tokens[tokenHash]
	if !ok || token == nil {
		return nil, nil
	}
	if !token.ExpiresAt.After(time.Now().UTC()) {
		return nil, nil
	}
	cp := *token
	return &cp, nil
}

func (r *adminAPITokenRepoStub) RotateToken(ctx context.Context, id, oldHash, newHash string, expiresAt time.Time, isBootstrap bool) (bool, error) {
	token, ok := r.tokens[oldHash]
	if !ok || token == nil {
		return false, nil
	}
	if token.ID != id {
		return false, nil
	}
	delete(r.tokens, oldHash)
	r.tokens[newHash] = &entity.AdminAPIToken{
		ID:          id,
		TokenHash:   newHash,
		ExpiresAt:   expiresAt,
		IsBootstrap: isBootstrap,
	}
	return true, nil
}

func (r *adminAPITokenRepoStub) PurgeExpired(ctx context.Context, limit int64) (int64, error) {
	now := time.Now().UTC()
	var deleted int64
	for hash, token := range r.tokens {
		if token == nil || !token.ExpiresAt.After(now) {
			delete(r.tokens, hash)
			deleted++
		}
	}
	return deleted, nil
}

func TestEnsureBootstrapTokenCachesHashOnly(t *testing.T) {
	ctx := context.Background()
	secret := "test-admin-secret-ensure"

	repo := &adminAPITokenRepoStub{
		tokens: make(map[string]*entity.AdminAPIToken),
	}
	svc := service.NewAdminAPITokenService(repo, &fakeSecretProvider{
		active: security.SecretVersion{
			Version: 1,
			Value:   secret,
		},
	}, &config.Config{})

	token, created, err := svc.EnsureBootstrapToken(ctx)
	if err != nil {
		t.Fatalf("EnsureBootstrapToken returned error: %v", err)
	}
	if !created {
		t.Fatalf("expected bootstrap token to be created")
	}
	if token == "" {
		t.Fatalf("expected plaintext token to be returned once")
	}

	ok, err := svc.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if !ok {
		t.Fatalf("expected token to validate")
	}
}

func TestValidateCachesHashOnly(t *testing.T) {
	ctx := context.Background()
	secret := "test-admin-secret-validate"
	token := "candidate-admin-token"

	tokenHash, err := security.HashToken(token, secret)
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}

	repo := &adminAPITokenRepoStub{
		tokens: map[string]*entity.AdminAPIToken{
			tokenHash: &entity.AdminAPIToken{
				ID:          "admin-token-1",
				TokenHash:   tokenHash,
				ExpiresAt:   time.Now().UTC().Add(time.Hour),
				IsBootstrap: false,
			},
		},
	}
	svc := service.NewAdminAPITokenService(repo, &fakeSecretProvider{
		active: security.SecretVersion{
			Version: 1,
			Value:   secret,
		},
	}, &config.Config{})

	ok, err := svc.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if !ok {
		t.Fatalf("expected token to validate")
	}
	if repo.existsHit != 1 {
		t.Fatalf("expected one repository check, got %d", repo.existsHit)
	}

	// Second call should be cached.
	ok, err = svc.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate second call returned error: %v", err)
	}
	if !ok {
		t.Fatalf("expected token to validate on cached path")
	}
	if repo.existsHit != 1 {
		t.Fatalf("expected cached validation without extra repository call, got %d", repo.existsHit)
	}
}
