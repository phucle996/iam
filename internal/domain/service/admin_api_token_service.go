package domainsvc

import (
	"context"

	"iam/internal/domain/entity"
)

type AdminAPITokenService interface {
	EnsureBootstrapToken(ctx context.Context) (token string, created bool, err error)
	Authorize(ctx context.Context, token string) (*entity.AdminAPIAuthorization, error)
	Validate(ctx context.Context, token string) (bool, error)
}
