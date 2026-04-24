package domainrepo

import (
	"context"
	"iam/internal/domain/entity"
)

type AdminAPITokenRepository interface {
	HasAdminAPITokens(ctx context.Context) (bool, error)
	CreateAdminAPIToken(ctx context.Context, token *entity.AdminAPIToken) error
	ExistsAdminAPITokenHash(ctx context.Context, tokenHash string) (bool, error)
}
