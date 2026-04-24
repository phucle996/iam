package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"iam/internal/domain/entity"
	domainsvc "iam/internal/domain/service"
	"iam/internal/transport/http/handler"
	"iam/pkg/errorx"
	"iam/pkg/logger"

	"github.com/gin-gonic/gin"
)

var _ domainsvc.OAuthService = (*stubOAuthHandlerService)(nil)

type stubOAuthHandlerService struct {
	authorizeResult *entity.OAuthAuthorizePreview
	authorizeErr    error
	tokenResult     *entity.OAuthTokenResponse
	tokenErr        error
	createResult    *entity.OAuthClientWithSecret
	createErr       error
}

func (s *stubOAuthHandlerService) Authorize(ctx context.Context, req *entity.OAuthAuthorizeRequest) (*entity.OAuthAuthorizePreview, error) {
	return s.authorizeResult, s.authorizeErr
}
func (s *stubOAuthHandlerService) Decide(ctx context.Context, req *entity.OAuthAuthorizeDecision) (*entity.OAuthAuthorizeDecisionResult, error) {
	return &entity.OAuthAuthorizeDecisionResult{}, nil
}
func (s *stubOAuthHandlerService) Token(ctx context.Context, req *entity.OAuthTokenRequest, clientID, clientSecret string) (*entity.OAuthTokenResponse, error) {
	if s.tokenResult != nil || s.tokenErr != nil {
		return s.tokenResult, s.tokenErr
	}
	return &entity.OAuthTokenResponse{AccessToken: "token", TokenType: "Bearer", ExpiresIn: 60}, nil
}
func (s *stubOAuthHandlerService) Revoke(ctx context.Context, req *entity.OAuthRevokeRequest, clientID, clientSecret string) error {
	return nil
}
func (s *stubOAuthHandlerService) Introspect(ctx context.Context, req *entity.OAuthIntrospectRequest, clientID, clientSecret string) (*entity.OAuthIntrospection, error) {
	return &entity.OAuthIntrospection{Active: false}, nil
}
func (s *stubOAuthHandlerService) CreateClient(ctx context.Context, req *entity.OAuthClientCreateRequest) (*entity.OAuthClientWithSecret, error) {
	if s.createResult != nil || s.createErr != nil {
		return s.createResult, s.createErr
	}
	return &entity.OAuthClientWithSecret{
		Client:       &entity.OAuthClient{ClientID: "client-a", Name: "Client A", IsActive: true},
		ClientSecret: "secret",
	}, nil
}
func (s *stubOAuthHandlerService) ListClients(ctx context.Context, limit, offset int) ([]*entity.OAuthClient, error) {
	return nil, nil
}
func (s *stubOAuthHandlerService) GetClient(ctx context.Context, clientID string) (*entity.OAuthClient, error) {
	return nil, nil
}
func (s *stubOAuthHandlerService) UpdateClient(ctx context.Context, req *entity.OAuthClientUpdateRequest) (*entity.OAuthClient, error) {
	return nil, nil
}
func (s *stubOAuthHandlerService) DeleteClient(ctx context.Context, clientID string) error {
	return nil
}
func (s *stubOAuthHandlerService) RotateClientSecret(ctx context.Context, clientID string) (*entity.OAuthClientWithSecret, error) {
	return nil, nil
}
func (s *stubOAuthHandlerService) ListMyGrants(ctx context.Context, userID string) ([]*entity.OAuthUserGrant, error) {
	return nil, nil
}
func (s *stubOAuthHandlerService) RevokeMyGrant(ctx context.Context, userID, clientID string) error {
	return nil
}
func (s *stubOAuthHandlerService) AdminRevokeGrant(ctx context.Context, userID, clientID string) error {
	return nil
}

func TestOAuthHandlerAuthorizeRequiresUserSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()

	h := handler.NewOAuthHandler(&stubOAuthHandlerService{})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/oauth/authorize?response_type=code&client_id=client-a&redirect_uri=https://app.example/cb&code_challenge=x&code_challenge_method=S256", nil)
	c.Request = req

	h.Authorize(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestOAuthHandlerTokenMapsInvalidClientToOAuthError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()

	h := handler.NewOAuthHandler(&stubOAuthHandlerService{tokenErr: errorx.ErrOAuthInvalidClient})

	body, err := json.Marshal(gin.H{
		"grant_type":    "client_credentials",
		"client_id":     "client-a",
		"client_secret": "wrong",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/oauth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.Token(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("invalid_client")) {
		t.Fatalf("expected oauth invalid_client response, got %s", w.Body.String())
	}
}

func TestOAuthHandlerAdminCreateClientReturnsSecretOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()

	h := handler.NewOAuthHandler(&stubOAuthHandlerService{createResult: &entity.OAuthClientWithSecret{
		Client: &entity.OAuthClient{
			ClientID:  "client-a",
			Name:      "Client A",
			IsActive:  true,
			CreatedAt: time.Now().UTC(),
		},
		ClientSecret: "super-secret",
	}})

	body, err := json.Marshal(gin.H{
		"name":           "Client A",
		"redirect_uris":  []string{"https://app.example/cb"},
		"allowed_scopes": []string{"profile"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/admin/oauth/clients", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.AdminCreateClient(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("client_secret")) {
		t.Fatalf("expected client_secret in response, got %s", w.Body.String())
	}
}
