package service

import (
	"context"
	"strings"
	"sync"
	"time"

	"controlplane/internal/config"
	"controlplane/internal/domain/entity"
	domainrepo "controlplane/internal/domain/repository"
	"controlplane/internal/security"
	"controlplane/pkg/id"
)

const (
	adminAPITokenLength           = 48
	defaultAdminAPITokenTTL       = 15 * time.Minute
	defaultAdminAPITokenRotateGap = 5 * time.Minute
)

type adminTokenCacheEntry struct {
	expiresAt   time.Time
	isBootstrap bool
}

type AdminAPITokenService struct {
	repo    domainrepo.AdminAPITokenRepository
	secrets security.SecretProvider
	cfg     *config.Config

	mu          sync.RWMutex
	validHashes map[string]adminTokenCacheEntry
	cacheVer    int64
}

func NewAdminAPITokenService(repo domainrepo.AdminAPITokenRepository, secrets security.SecretProvider, cfg *config.Config) *AdminAPITokenService {
	return &AdminAPITokenService{
		repo:        repo,
		secrets:     secrets,
		cfg:         cfg,
		validHashes: make(map[string]adminTokenCacheEntry),
	}
}

func (s *AdminAPITokenService) EnsureBootstrapToken(ctx context.Context) (string, bool, error) {
	if s == nil || s.repo == nil || s.secrets == nil {
		return "", false, nil
	}

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

	token, err := security.GenerateToken(adminAPITokenLength, active.Value)
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

	expiresAt := time.Now().UTC().Add(s.adminTokenTTL())
	if err := s.repo.CreateAdminAPIToken(ctx, &entity.AdminAPIToken{
		ID:          tokenID,
		TokenHash:   tokenHash,
		ExpiresAt:   expiresAt,
		IsBootstrap: true,
	}); err != nil {
		return "", false, err
	}

	s.cacheHash(tokenHash, adminTokenCacheEntry{expiresAt: expiresAt, isBootstrap: true})
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

	now := time.Now().UTC()
	rotateBefore := s.adminTokenRotateBefore()

	for _, candidate := range candidates {
		tokenHash, err := security.HashToken(token, candidate.Value)
		if err != nil {
			return nil, err
		}

		if entry, ok := s.getCacheEntry(tokenHash, now); ok {
			if !entry.isBootstrap && entry.expiresAt.Sub(now) > rotateBefore {
				return &entity.AdminAPIAuthorization{
					Valid:       true,
					CookieToken: token,
					ExpiresAt:   entry.expiresAt,
				}, nil
			}
		}

		record, err := s.repo.GetActiveByHash(ctx, tokenHash)
		if err != nil {
			return nil, err
		}
		if record == nil {
			continue
		}

		if record.IsBootstrap || record.ExpiresAt.Sub(now) <= rotateBefore {
			active := candidates[0]
			newToken, err := security.GenerateToken(adminAPITokenLength, active.Value)
			if err != nil {
				return nil, err
			}
			newHash, err := security.HashToken(newToken, active.Value)
			if err != nil {
				return nil, err
			}
			newExpiresAt := now.Add(s.adminTokenTTL())

			rotated, err := s.repo.RotateToken(ctx, record.ID, tokenHash, newHash, newExpiresAt, false)
			if err != nil {
				return nil, err
			}
			if !rotated {
				return &entity.AdminAPIAuthorization{Valid: false}, nil
			}

			s.removeHash(tokenHash)
			s.cacheHash(newHash, adminTokenCacheEntry{expiresAt: newExpiresAt, isBootstrap: false})
			return &entity.AdminAPIAuthorization{
				Valid:       true,
				CookieToken: newToken,
				ExpiresAt:   newExpiresAt,
			}, nil
		}

		s.cacheHash(tokenHash, adminTokenCacheEntry{expiresAt: record.ExpiresAt, isBootstrap: false})
		return &entity.AdminAPIAuthorization{
			Valid:       true,
			CookieToken: token,
			ExpiresAt:   record.ExpiresAt,
		}, nil
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

func (s *AdminAPITokenService) PurgeExpired(ctx context.Context, limit int64) (int64, error) {
	if s == nil || s.repo == nil {
		return 0, nil
	}
	deleted, err := s.repo.PurgeExpired(ctx, limit)
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	s.pruneCache(now)
	return deleted, nil
}

func (s *AdminAPITokenService) getCacheEntry(tokenHash string, now time.Time) (adminTokenCacheEntry, bool) {
	s.mu.RLock()
	entry, ok := s.validHashes[tokenHash]
	s.mu.RUnlock()
	if !ok {
		return adminTokenCacheEntry{}, false
	}
	if !entry.expiresAt.After(now) {
		s.removeHash(tokenHash)
		return adminTokenCacheEntry{}, false
	}
	return entry, true
}

func (s *AdminAPITokenService) cacheHash(tokenHash string, entry adminTokenCacheEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.validHashes[tokenHash] = entry
}

func (s *AdminAPITokenService) removeHash(tokenHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.validHashes, tokenHash)
}

func (s *AdminAPITokenService) pruneCache(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for tokenHash, entry := range s.validHashes {
		if !entry.expiresAt.After(now) {
			delete(s.validHashes, tokenHash)
		}
	}
}

func (s *AdminAPITokenService) syncCacheVersion(version int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cacheVer == version {
		return
	}
	s.cacheVer = version
	s.validHashes = make(map[string]adminTokenCacheEntry)
}

func (s *AdminAPITokenService) adminTokenTTL() time.Duration {
	if s == nil || s.cfg == nil {
		return defaultAdminAPITokenTTL
	}
	if s.cfg.Security.AdminAPITokenTTL <= 0 {
		return defaultAdminAPITokenTTL
	}
	return s.cfg.Security.AdminAPITokenTTL
}

func (s *AdminAPITokenService) adminTokenRotateBefore() time.Duration {
	ttl := s.adminTokenTTL()
	if s == nil || s.cfg == nil {
		if defaultAdminAPITokenRotateGap >= ttl {
			return ttl / 2
		}
		return defaultAdminAPITokenRotateGap
	}

	value := s.cfg.Security.AdminAPITokenRotateBefore
	if value <= 0 {
		value = defaultAdminAPITokenRotateGap
	}
	if value >= ttl {
		return ttl / 2
	}
	return value
}
