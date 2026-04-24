package svc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"iam/internal/config"
	"iam/internal/domain/entity"
	"iam/internal/security"
	"iam/internal/service"
	"iam/pkg/errorx"
)

type oauthRepoStub struct {
	client *entity.OAuthClient
}

func (r *oauthRepoStub) CreateClient(ctx context.Context, client *entity.OAuthClient) error {
	if r != nil {
		r.client = client
	}
	return nil
}
func (r *oauthRepoStub) ListClients(ctx context.Context, limit, offset int) ([]*entity.OAuthClient, error) {
	return nil, nil
}
func (r *oauthRepoStub) GetClientByClientID(ctx context.Context, clientID string) (*entity.OAuthClient, error) {
	if r != nil && r.client != nil && r.client.ClientID == clientID {
		cp := *r.client
		return &cp, nil
	}
	return nil, errorx.ErrOAuthClientNotFound
}
func (r *oauthRepoStub) GetClientByID(ctx context.Context, id string) (*entity.OAuthClient, error) {
	if r != nil && r.client != nil && r.client.ID == id {
		cp := *r.client
		return &cp, nil
	}
	return nil, errorx.ErrOAuthClientNotFound
}
func (r *oauthRepoStub) UpdateClient(ctx context.Context, client *entity.OAuthClient) error {
	return nil
}
func (r *oauthRepoStub) DeleteClientByClientID(ctx context.Context, clientID string) error {
	return nil
}
func (r *oauthRepoStub) RotateClientSecret(ctx context.Context, clientID, secretHash string, rotatedAt time.Time) error {
	return nil
}
func (r *oauthRepoStub) GetGrant(ctx context.Context, userID, clientID string) (*entity.OAuthGrant, error) {
	return nil, errorx.ErrOAuthGrantNotFound
}
func (r *oauthRepoStub) UpsertGrant(ctx context.Context, grant *entity.OAuthGrant) error { return nil }
func (r *oauthRepoStub) ListGrantsByUser(ctx context.Context, userID string) ([]*entity.OAuthGrant, error) {
	return nil, nil
}
func (r *oauthRepoStub) RevokeGrant(ctx context.Context, userID, clientID string) error { return nil }
func (r *oauthRepoStub) RevokeGrantsByClient(ctx context.Context, clientID string) (int64, error) {
	return 0, nil
}
func (r *oauthRepoStub) CreateAuthorizationCode(ctx context.Context, code *entity.OAuthAuthorizationCode) error {
	return nil
}
func (r *oauthRepoStub) ConsumeAuthorizationCode(ctx context.Context, codeHash string, consumedAt time.Time) (*entity.OAuthAuthorizationCode, error) {
	return nil, errorx.ErrOAuthCodeNotFound
}
func (r *oauthRepoStub) CreateRefreshToken(ctx context.Context, token *entity.OAuthRefreshToken) error {
	return nil
}
func (r *oauthRepoStub) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*entity.OAuthRefreshToken, error) {
	return nil, errorx.ErrOAuthInvalidGrant
}
func (r *oauthRepoStub) ConsumeRefreshToken(ctx context.Context, tokenHash string, replacedByID string, revokedAt time.Time) (*entity.OAuthRefreshToken, error) {
	return nil, errorx.ErrOAuthInvalidGrant
}
func (r *oauthRepoStub) RevokeRefreshTokenByHash(ctx context.Context, tokenHash string, revokedAt time.Time) (bool, error) {
	return false, nil
}

func TestOAuthServiceCreateClientRejectsInvalidScope(t *testing.T) {
	svc := service.NewOAuthService(
		&oauthRepoStub{},
		&fakeSecretProvider{},
		&config.Config{App: config.AppCfg{OAuthAllowedScopes: []string{"profile"}}},
		nil,
	)

	_, err := svc.CreateClient(context.Background(), &entity.OAuthClientCreateRequest{
		Name:          "client-a",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedScopes: []string{"admin"},
		IsActive:      true,
	})
	if !errors.Is(err, errorx.ErrOAuthInvalidScope) {
		t.Fatalf("expected ErrOAuthInvalidScope, got %v", err)
	}
}

func TestOAuthServiceAuthorizeRejectsUnsupportedResponseType(t *testing.T) {
	svc := service.NewOAuthService(
		&oauthRepoStub{},
		&fakeSecretProvider{},
		&config.Config{App: config.AppCfg{OAuthAllowedScopes: []string{"profile"}}},
		nil,
	)

	_, err := svc.Authorize(context.Background(), &entity.OAuthAuthorizeRequest{
		UserID:              "user-1",
		ResponseType:        "token",
		ClientID:            "client-1",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "profile",
		State:               "state-1",
		CodeChallenge:       "abc",
		CodeChallengeMethod: "S256",
	})
	if !errors.Is(err, errorx.ErrOAuthUnsupportedRespType) {
		t.Fatalf("expected ErrOAuthUnsupportedRespType, got %v", err)
	}
}

func TestOAuthServiceTokenRejectsUnsupportedGrantType(t *testing.T) {
	secret := "oauth-secret-v1"
	sum := sha256.Sum256([]byte("client-secret"))
	hash := hex.EncodeToString(sum[:])

	repo := &oauthRepoStub{
		client: &entity.OAuthClient{
			ID:               "client-id-1",
			ClientID:         "client-a",
			ClientSecretHash: hash,
			IsActive:         true,
		},
	}

	svc := service.NewOAuthService(
		repo,
		&fakeSecretProvider{active: security.SecretVersion{Value: secret}},
		&config.Config{App: config.AppCfg{OAuthAllowedScopes: []string{"profile"}}},
		nil,
	)

	_, err := svc.Token(context.Background(), &entity.OAuthTokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:custom",
	}, "client-a", "client-secret")
	if !errors.Is(err, errorx.ErrOAuthUnsupportedGrantType) {
		t.Fatalf("expected ErrOAuthUnsupportedGrantType, got %v", err)
	}
}
