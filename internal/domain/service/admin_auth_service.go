package domainsvc

import (
	"context"

	"iam/internal/domain/entity"
)

type AdminAuthService interface {
	EnsureBootstrapCredential(ctx context.Context) (*entity.AdminBootstrapResult, error)
	Login(ctx context.Context, input entity.AdminLoginInput) (*entity.AdminLoginResult, error)
	AuthorizeSession(ctx context.Context, input entity.AdminSessionAuthInput) (*entity.AdminSessionContext, error)
	Logout(ctx context.Context, sessionToken string) error
}
