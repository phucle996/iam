package handler_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"controlplane/internal/domain/entity"
	"controlplane/internal/transport/http/handler"
	"controlplane/pkg/errorx"
	"controlplane/pkg/logger"

	"github.com/gin-gonic/gin"
)

type stubTokenHandlerService struct {
	rotateErr    error
	rotateResult *entity.TokenResult
}

func (s *stubTokenHandlerService) IssueAfterLogin(ctx context.Context, user *entity.User, device *entity.Device) (*entity.TokenResult, error) {
	return &entity.TokenResult{}, nil
}
func (s *stubTokenHandlerService) IssueForMFA(ctx context.Context, userID, deviceID string) (*entity.TokenResult, error) {
	return &entity.TokenResult{}, nil
}
func (s *stubTokenHandlerService) Rotate(ctx context.Context, req *entity.RotateToken) (*entity.TokenResult, error) {
	if s.rotateErr != nil {
		return nil, s.rotateErr
	}
	if s.rotateResult != nil {
		return s.rotateResult, nil
	}
	return &entity.TokenResult{}, nil
}
func (s *stubTokenHandlerService) RevokeByRaw(ctx context.Context, rawRefreshToken string) error {
	return nil
}
func (s *stubTokenHandlerService) RevokeAllByUser(ctx context.Context, userID string) error {
	return nil
}
func (s *stubTokenHandlerService) CleanupExpired(ctx context.Context) (int64, error) {
	return 0, nil
}

func TestTokenHandlerRefreshMapsUnboundDeviceToUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	h := handler.NewTokenHandler(&stubTokenHandlerService{rotateErr: errorx.ErrRefreshDeviceUnbound})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte(`{
		"jti":"jti-1",
		"iat":1,
		"htm":"POST",
		"htu":"https://controlplane.example.com/api/v1/auth/refresh",
		"token_hash":"refresh-token-hash",
		"device_id":"device-1",
		"signature":"sig"
	}`)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh-token"})
	req.AddCookie(&http.Cookie{Name: "device_id", Value: "device-1"})
	c.Request = req

	h.Refresh(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unbound device refresh, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("refresh token is invalid or expired")) {
		t.Fatalf("expected generic unauthorized response, got %s", w.Body.String())
	}
}

func TestTokenHandlerRefreshSetsCookiesOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	h := handler.NewTokenHandler(&stubTokenHandlerService{
		rotateResult: &entity.TokenResult{
			AccessToken:           "access-token",
			RefreshToken:          "refresh-token",
			DeviceID:              "device-1",
			AccessTokenExpiresAt:  time.Now().Add(time.Minute),
			RefreshTokenExpiresAt: time.Now().Add(2 * time.Minute),
		},
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte(`{
		"jti":"jti-1",
		"iat":1710000000,
		"htm":"POST",
		"htu":"https://controlplane.example.com/api/v1/auth/refresh",
		"token_hash":"refresh-token-hash",
		"device_id":"device-1",
		"signature":"sig"
	}`)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh-token"})
	req.AddCookie(&http.Cookie{Name: "device_id", Value: "device-1"})
	c.Request = req

	h.Refresh(c)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for successful refresh, got %d", w.Code)
	}
	if len(bytes.TrimSpace(w.Body.Bytes())) != 0 {
		t.Fatalf("expected empty body for cookie-only refresh, got %s", w.Body.String())
	}

	resp := w.Result()
	defer resp.Body.Close()
	cookies := map[string]*http.Cookie{}
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = cookie
	}
	for _, name := range []string{"access_token", "refresh_token", "device_id", "refresh_token_hash"} {
		if _, ok := cookies[name]; !ok {
			t.Fatalf("expected %s cookie to be set", name)
		}
	}
	if !cookies["access_token"].HttpOnly || !cookies["refresh_token"].HttpOnly {
		t.Fatalf("expected auth cookies to be HttpOnly")
	}
	if cookies["device_id"].HttpOnly || cookies["refresh_token_hash"].HttpOnly {
		t.Fatalf("expected companion cookies to be readable")
	}
}

func TestTokenHandlerRefreshMissingRefreshCookieReturnsGenericUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	h := handler.NewTokenHandler(&stubTokenHandlerService{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte(`{
		"jti":"jti-1",
		"iat":1710000000,
		"htm":"POST",
		"htu":"https://controlplane.example.com/api/v1/auth/refresh",
		"token_hash":"refresh-token-hash",
		"device_id":"device-1",
		"signature":"sig"
	}`)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "device_id", Value: "device-1"})
	c.Request = req

	h.Refresh(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("unauthorized")) {
		t.Fatalf("expected generic unauthorized response, got %s", w.Body.String())
	}
}

func TestTokenHandlerRefreshMissingDeviceCookieReturnsGenericUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	h := handler.NewTokenHandler(&stubTokenHandlerService{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte(`{
		"jti":"jti-1",
		"iat":1710000000,
		"htm":"POST",
		"htu":"https://controlplane.example.com/api/v1/auth/refresh",
		"token_hash":"refresh-token-hash",
		"device_id":"device-1",
		"signature":"sig"
	}`)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh-token"})
	c.Request = req

	h.Refresh(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("unauthorized")) {
		t.Fatalf("expected generic unauthorized response, got %s", w.Body.String())
	}
}
