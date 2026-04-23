package domainrepo

import (
	"context"
	"controlplane/internal/domain/entity"
	"time"
)

type AdminAPITokenRepository interface {
	HasAdminAPITokens(ctx context.Context) (bool, error)
	CreateAdminAPIToken(ctx context.Context, token *entity.AdminAPIToken) error
	ExistsAdminAPITokenHash(ctx context.Context, tokenHash string) (bool, error)
	GetActiveByHash(ctx context.Context, tokenHash string) (*entity.AdminAPIToken, error)
	RotateToken(ctx context.Context, id, oldHash, newHash string, expiresAt time.Time, isBootstrap bool) (bool, error)
	PurgeExpired(ctx context.Context, limit int64) (int64, error)
}
