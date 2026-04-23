package domainsvc

import (
	"context"

	"controlplane/internal/domain/entity"
)

type AdminAPITokenService interface {
	EnsureBootstrapToken(ctx context.Context) (token string, created bool, err error)
	Authorize(ctx context.Context, token string) (*entity.AdminAPIAuthorization, error)
	Validate(ctx context.Context, token string) (bool, error)
	PurgeExpired(ctx context.Context, limit int64) (int64, error)
}
