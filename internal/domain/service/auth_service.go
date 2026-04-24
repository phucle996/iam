package domainsvc

import (
	"context"

	"iam/internal/domain/entity"
)

// AuthService defines primary authentication actions.
type AuthService interface {
	Login(ctx context.Context, username, password, deviceFingerprint, devicePublicKey, deviceKeyAlgorithm string) (*entity.LoginResult, error)
	AdminAPIKeyLogin(ctx context.Context, apiKey string) error
	Register(ctx context.Context, user *entity.User, profile *entity.UserProfile, rawPassword string) error
	WhoAmI(ctx context.Context, userID string) (*entity.WhoAmI, error)
	Activate(ctx context.Context, token string) error
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	Logout(ctx context.Context, jti string, rawRefreshToken string) error
}
