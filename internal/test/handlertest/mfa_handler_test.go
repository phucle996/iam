package handler_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"iam/internal/domain/entity"
	"iam/internal/transport/http/handler"
	"iam/internal/transport/http/middleware"
	"iam/pkg/errorx"
	"iam/pkg/logger"
	"errors"

	"github.com/gin-gonic/gin"
)

type stubMfaHandlerService struct {
	verifyUserID      string
	verifyDeviceID    string
	verifyErr         error
	enrollResult      [2]string
	enrollErr         error
	confirmErr        error
	listResult        []*entity.MfaSetting
	listErr           error
	enableErr         error
	disableErr        error
	deleteErr         error
	recoveryCodes     []string
	recoveryCodesErr  error
}

func (s *stubMfaHandlerService) CheckAndChallenge(ctx context.Context, userID, deviceID string) (bool, string, []string, error) {
	return false, "", nil, nil
}

func (s *stubMfaHandlerService) Verify(ctx context.Context, challengeID, method, code string) (string, string, error) {
	if s.verifyErr != nil {
		return "", "", s.verifyErr
	}
	if s.verifyUserID == "" {
		s.verifyUserID = "user-1"
	}
	if s.verifyDeviceID == "" {
		s.verifyDeviceID = "device-1"
	}
	return s.verifyUserID, s.verifyDeviceID, nil
}

func (s *stubMfaHandlerService) EnrollTOTP(ctx context.Context, userID, deviceName string) (string, string, error) {
	return s.enrollResult[0], s.enrollResult[1], s.enrollErr
}

func (s *stubMfaHandlerService) ConfirmTOTP(ctx context.Context, userID, settingID, code string) error {
	return s.confirmErr
}

func (s *stubMfaHandlerService) ListMethods(ctx context.Context, userID string) ([]*entity.MfaSetting, error) {
	return s.listResult, s.listErr
}

func (s *stubMfaHandlerService) EnableMethod(ctx context.Context, userID, settingID string) error {
	return s.enableErr
}

func (s *stubMfaHandlerService) DisableMethod(ctx context.Context, userID, settingID string) error {
	return s.disableErr
}

func (s *stubMfaHandlerService) DeleteMethod(ctx context.Context, userID, settingID string) error {
	return s.deleteErr
}

func (s *stubMfaHandlerService) GenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	return s.recoveryCodes, s.recoveryCodesErr
}

func TestMfaHandlerVerifySetsCookiesOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	h := handler.NewMfaHandler(&stubMfaHandlerService{}, &stubTokenHandlerService{
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
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader([]byte(`{"challenge_id":"challenge-1","method":"totp","code":"123456"}`)))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.Verify(c)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for successful mfa verify, got %d", w.Code)
	}
	if len(bytes.TrimSpace(w.Body.Bytes())) != 0 {
		t.Fatalf("expected empty body for cookie-only mfa verify, got %s", w.Body.String())
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

func TestMfaHandlerVerifyErrorMappings(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()

	tests := []struct {
		err  error
		code int
	}{
		{errorx.ErrMfaChallengeNotFound, http.StatusUnauthorized},
		{errorx.ErrMfaCodeInvalid, http.StatusUnauthorized},
		{errorx.ErrMfaCodeExpired, http.StatusUnauthorized},
		{errorx.ErrMfaMethodNotAllowed, http.StatusBadRequest},
		{errors.New("generic"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			svc := &stubMfaHandlerService{verifyErr: tt.err}
			h := handler.NewMfaHandler(svc, &stubTokenHandlerService{})
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader([]byte(`{"challenge_id":"c","method":"totp","code":"1"}`)))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req
			h.Verify(c)
			if w.Code != tt.code {
				t.Fatalf("expected %d for %v, got %d", tt.code, tt.err, w.Code)
			}
		})
	}
}

func TestMfaHandlerListMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubMfaHandlerService{
		listResult: []*entity.MfaSetting{
			{ID: "m1", MfaType: "totp", IsEnabled: true},
		},
	}
	h := handler.NewMfaHandler(svc, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/mfa", nil)
	c.Request = req
	c.Set(middleware.CtxKeyUserID, "u1")

	h.ListMethods(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"ID":"m1"`)) {
		t.Fatalf("expected method list in response, got %s", w.Body.String())
	}
}

func TestMfaHandlerEnrollTOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubMfaHandlerService{
		enrollResult: [2]string{"s1", "otpauth://..."},
	}
	h := handler.NewMfaHandler(svc, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/mfa/totp/enroll", bytes.NewReader([]byte(`{"device_name":"d1"}`)))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	c.Set(middleware.CtxKeyUserID, "u1")

	h.EnrollTOTP(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"setting_id":"s1"`)) {
		t.Fatalf("expected setting_id in response, got %s", w.Body.String())
	}
}

func TestMfaHandlerConfirmTOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubMfaHandlerService{}
	h := handler.NewMfaHandler(svc, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/mfa/totp/confirm", bytes.NewReader([]byte(`{"setting_id":"s1","code":"123456"}`)))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	c.Set(middleware.CtxKeyUserID, "u1")

	h.ConfirmTOTP(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMfaHandlerMethodActions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubMfaHandlerService{}
	h := handler.NewMfaHandler(svc, nil)

	actions := []struct {
		name   string
		method func(*gin.Context)
		verb   string
		path   string
	}{
		{"Enable", h.EnableMethod, http.MethodPatch, "/api/v1/me/mfa/m1/enable"},
		{"Disable", h.DisableMethod, http.MethodPatch, "/api/v1/me/mfa/m1/disable"},
		{"Delete", h.DeleteMethod, http.MethodDelete, "/api/v1/me/mfa/m1"},
	}

	for _, tt := range actions {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req, _ := http.NewRequest(tt.verb, tt.path, nil)
			c.Request = req
			c.Params = append(c.Params, gin.Param{Key: "setting_id", Value: "m1"})
			c.Set(middleware.CtxKeyUserID, "u1")

			tt.method(c)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200 for %s, got %d", tt.name, w.Code)
			}
		})
	}
}

func TestMfaHandlerGenerateRecoveryCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubMfaHandlerService{
		recoveryCodes: []string{"c1", "c2"},
	}
	h := handler.NewMfaHandler(svc, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/mfa/recovery-codes", nil)
	c.Request = req
	c.Set(middleware.CtxKeyUserID, "u1")

	h.GenerateRecoveryCodes(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"recovery_codes":["c1","c2"]`)) {
		t.Fatalf("expected codes in response, got %s", w.Body.String())
	}
}
