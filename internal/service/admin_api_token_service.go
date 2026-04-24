package service

import (
	"context"
	"strings"
	"sync"

	"iam/internal/domain/entity"
	domainrepo "iam/internal/domain/repository"
	"iam/internal/security"
	"iam/pkg/id"
)

type AdminAPITokenService struct {
	repo    domainrepo.AdminAPITokenRepository
	secrets security.SecretProvider

	mu          sync.RWMutex
	validHashes map[string]struct{}
	cacheVer    int64
}

func NewAdminAPITokenService(repo domainrepo.AdminAPITokenRepository, secrets security.SecretProvider) *AdminAPITokenService {
	return &AdminAPITokenService{
		repo:        repo,
		secrets:     secrets,
		validHashes: make(map[string]struct{}),
	}
}

func (s *AdminAPITokenService) EnsureBootstrapToken(ctx context.Context) (string, bool, error) {

	hasAny, err := s.repo.HasAdminAPITokens(ctx)
	if err != nil {
		return "", false, err
	}
	if hasAny {
		return "", false, nil
	}

	active, err := s.secrets.GetActive(security.SecretFamilyAdminAPI)
	if err != nil {
		return "", false, err
	}
	s.syncCacheVersion(active.Version)

	token, err := security.GenerateToken(256, active.Value)
	if err != nil {
		return "", false, err
	}

	tokenHash, err := security.HashToken(token, active.Value)
	if err != nil {
		return "", false, err
	}

	tokenID, err := id.Generate()
	if err != nil {
		return "", false, err
	}

	if err := s.repo.CreateAdminAPIToken(ctx, &entity.AdminAPIToken{
		ID:        tokenID,
		TokenHash: tokenHash,
	}); err != nil {
		return "", false, err
	}

	s.cacheHash(tokenHash)
	return token, true, nil
}

func (s *AdminAPITokenService) Authorize(ctx context.Context, token string) (*entity.AdminAPIAuthorization, error) {
	if s == nil || s.repo == nil || s.secrets == nil {
		return &entity.AdminAPIAuthorization{Valid: false}, nil
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return &entity.AdminAPIAuthorization{Valid: false}, nil
	}

	candidates, err := s.secrets.GetCandidates(security.SecretFamilyAdminAPI)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return &entity.AdminAPIAuthorization{Valid: false}, security.ErrSecretUnavailable
	}
	s.syncCacheVersion(candidates[0].Version)

	for _, candidate := range candidates {
		tokenHash, err := security.HashToken(token, candidate.Value)
		if err != nil {
			return nil, err
		}

		if s.hasCachedHash(tokenHash) {
			return &entity.AdminAPIAuthorization{Valid: true}, nil
		}

		exists, err := s.repo.ExistsAdminAPITokenHash(ctx, tokenHash)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}

		s.cacheHash(tokenHash)
		return &entity.AdminAPIAuthorization{Valid: true}, nil
	}

	return &entity.AdminAPIAuthorization{Valid: false}, nil
}

func (s *AdminAPITokenService) Validate(ctx context.Context, token string) (bool, error) {
	authz, err := s.Authorize(ctx, token)
	if err != nil {
		return false, err
	}
	if authz == nil {
		return false, nil
	}
	return authz.Valid, nil
}

func (s *AdminAPITokenService) hasCachedHash(tokenHash string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.validHashes[tokenHash]
	return ok
}

func (s *AdminAPITokenService) cacheHash(tokenHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.validHashes[tokenHash] = struct{}{}
}

func (s *AdminAPITokenService) syncCacheVersion(version int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cacheVer == version {
		return
	}
	s.cacheVer = version
	s.validHashes = make(map[string]struct{})
}
