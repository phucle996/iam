package domainrepo

import (
	"context"
	"iam/internal/domain/entity"
)

// UserRepository defines data access methods for User and UserProfile.
// CreateRefreshToken is kept here because it is called during the login flow by AuthService.
// Pure device CRUD lives in DeviceRepository.
type UserRepository interface {
	CreatePendingAccount(ctx context.Context, user *entity.User, profile *entity.UserProfile) error
	Activate(ctx context.Context, userID string) error
	GetByEmail(ctx context.Context, email string) (*entity.User, error)
	GetByUsername(ctx context.Context, username string) (*entity.User, error)
	GetByID(ctx context.Context, id string) (*entity.User, error)
	GetProfileByUserID(ctx context.Context, userID string) (*entity.UserProfile, error)
	GetWhoAmI(ctx context.Context, userID string) (*entity.WhoAmI, error)
	UpdatePassword(ctx context.Context, userID, newPasswordHash string) error
	CreateRefreshToken(ctx context.Context, token *entity.RefreshToken) error
}
