package domainsvc

import (
	"context"

	"iam/internal/domain/entity"
)

// OAuthService encapsulates OAuth2.1 core behavior.
type OAuthService interface {
	Authorize(ctx context.Context, req *entity.OAuthAuthorizeRequest) (*entity.OAuthAuthorizePreview, error)
	Decide(ctx context.Context, req *entity.OAuthAuthorizeDecision) (*entity.OAuthAuthorizeDecisionResult, error)
	Token(ctx context.Context, req *entity.OAuthTokenRequest, clientID, clientSecret string) (*entity.OAuthTokenResponse, error)
	Revoke(ctx context.Context, req *entity.OAuthRevokeRequest, clientID, clientSecret string) error
	Introspect(ctx context.Context, req *entity.OAuthIntrospectRequest, clientID, clientSecret string) (*entity.OAuthIntrospection, error)

	CreateClient(ctx context.Context, req *entity.OAuthClientCreateRequest) (*entity.OAuthClientWithSecret, error)
	ListClients(ctx context.Context, limit, offset int) ([]*entity.OAuthClient, error)
	GetClient(ctx context.Context, clientID string) (*entity.OAuthClient, error)
	UpdateClient(ctx context.Context, req *entity.OAuthClientUpdateRequest) (*entity.OAuthClient, error)
	DeleteClient(ctx context.Context, clientID string) error
	RotateClientSecret(ctx context.Context, clientID string) (*entity.OAuthClientWithSecret, error)

	ListMyGrants(ctx context.Context, userID string) ([]*entity.OAuthUserGrant, error)
	RevokeMyGrant(ctx context.Context, userID, clientID string) error
	AdminRevokeGrant(ctx context.Context, userID, clientID string) error
}
