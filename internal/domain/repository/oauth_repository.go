package domainrepo

import (
	"context"
	"iam/internal/domain/entity"
	"time"
)

// OAuthRepository persists OAuth clients, grants, auth codes, and refresh tokens.
type OAuthRepository interface {
	CreateClient(ctx context.Context, client *entity.OAuthClient) error
	ListClients(ctx context.Context, limit, offset int) ([]*entity.OAuthClient, error)
	GetClientByClientID(ctx context.Context, clientID string) (*entity.OAuthClient, error)
	GetClientByID(ctx context.Context, id string) (*entity.OAuthClient, error)
	UpdateClient(ctx context.Context, client *entity.OAuthClient) error
	DeleteClientByClientID(ctx context.Context, clientID string) error
	RotateClientSecret(ctx context.Context, clientID, secretHash string, rotatedAt time.Time) error

	GetGrant(ctx context.Context, userID, clientID string) (*entity.OAuthGrant, error)
	UpsertGrant(ctx context.Context, grant *entity.OAuthGrant) error
	ListGrantsByUser(ctx context.Context, userID string) ([]*entity.OAuthGrant, error)
	RevokeGrant(ctx context.Context, userID, clientID string) error
	RevokeGrantsByClient(ctx context.Context, clientID string) (int64, error)

	CreateAuthorizationCode(ctx context.Context, code *entity.OAuthAuthorizationCode) error
	ConsumeAuthorizationCode(ctx context.Context, codeHash string, consumedAt time.Time) (*entity.OAuthAuthorizationCode, error)

	CreateRefreshToken(ctx context.Context, token *entity.OAuthRefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*entity.OAuthRefreshToken, error)
	ConsumeRefreshToken(ctx context.Context, tokenHash string, replacedByID string, revokedAt time.Time) (*entity.OAuthRefreshToken, error)
	RevokeRefreshTokenByHash(ctx context.Context, tokenHash string, revokedAt time.Time) (bool, error)
}
