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
	"iam/internal/transport/http/handler"
	"iam/internal/transport/http/middleware"
	reqdto "iam/internal/transport/http/request"
	"iam/pkg/errorx"
	"iam/pkg/logger"
	"errors"

	"github.com/gin-gonic/gin"
)

type stubAuthHandlerService struct {
	loginCalled      bool
	loginErr         error
	loginResult      *entity.LoginResult
	adminLoginCalled bool
	adminLoginErr    error
	whoAmIResult     *entity.WhoAmI
	whoAmIErr        error
	registerCalled   bool
	registerErr      error
	activateCalled   bool
	activateErr      error
	forgotCalled     bool
	forgotErr        error
	resetCalled      bool
	resetErr         error
	logoutCalled     bool
	logoutErr        error
}

type stubAdminAuthHandlerService struct {
	loginCalled        bool
	loginInput         entity.AdminLoginInput
	loginResult        *entity.AdminLoginResult
	loginErr           error
	logoutCalled       bool
	logoutToken        string
	logoutErr          error
	authorizeCalled    bool
	authorizeInput     entity.AdminSessionAuthInput
	authorizeResult    *entity.AdminSessionContext
	authorizeResultErr error
}

func (s *stubAdminAuthHandlerService) EnsureBootstrapCredential(ctx context.Context) (*entity.AdminBootstrapResult, error) {
	return &entity.AdminBootstrapResult{Created: false}, nil
}
func (s *stubAdminAuthHandlerService) Login(ctx context.Context, input entity.AdminLoginInput) (*entity.AdminLoginResult, error) {
	s.loginCalled = true
	s.loginInput = input
	if s.loginResult != nil || s.loginErr != nil {
		return s.loginResult, s.loginErr
	}
	return &entity.AdminLoginResult{
		Admin: &entity.AdminUser{
			ID:          "admin-1",
			DisplayName: "System Admin",
		},
		SessionID:        "session-1",
		SessionToken:     "session-token",
		SessionExpiresAt: time.Now().UTC().Add(time.Hour),
		DeviceID:         "device-1",
		DeviceSecret:     "device-secret",
		DeviceExpiresAt:  time.Now().UTC().Add(30 * 24 * time.Hour),
	}, nil
}
func (s *stubAdminAuthHandlerService) AuthorizeSession(ctx context.Context, input entity.AdminSessionAuthInput) (*entity.AdminSessionContext, error) {
	s.authorizeCalled = true
	s.authorizeInput = input
	if s.authorizeResult != nil || s.authorizeResultErr != nil {
		return s.authorizeResult, s.authorizeResultErr
	}
	return &entity.AdminSessionContext{}, nil
}
func (s *stubAdminAuthHandlerService) Logout(ctx context.Context, sessionToken string) error {
	s.logoutCalled = true
	s.logoutToken = sessionToken
	return s.logoutErr
}

func (s *stubAuthHandlerService) Login(ctx context.Context, username, password, deviceFingerprint, devicePublicKey, deviceKeyAlgorithm string) (*entity.LoginResult, error) {
	s.loginCalled = true
	if s.loginResult != nil {
		return s.loginResult, s.loginErr
	}
	return &entity.LoginResult{}, s.loginErr
}
func (s *stubAuthHandlerService) AdminAPIKeyLogin(ctx context.Context, apiKey string) error {
	s.adminLoginCalled = true
	return s.adminLoginErr
}
func (s *stubAuthHandlerService) Register(ctx context.Context, user *entity.User, profile *entity.UserProfile, rawPassword string) error {
	s.registerCalled = true
	return s.registerErr
}
func (s *stubAuthHandlerService) WhoAmI(ctx context.Context, userID string) (*entity.WhoAmI, error) {
	if s.whoAmIErr != nil {
		return nil, s.whoAmIErr
	}
	if s.whoAmIResult != nil {
		return s.whoAmIResult, nil
	}
	return &entity.WhoAmI{}, nil
}
func (s *stubAuthHandlerService) Activate(ctx context.Context, token string) error {
	s.activateCalled = true
	return s.activateErr
}
func (s *stubAuthHandlerService) ForgotPassword(ctx context.Context, email string) error {
	s.forgotCalled = true
	return s.forgotErr
}
func (s *stubAuthHandlerService) ResetPassword(ctx context.Context, token, newPassword string) error {
	s.resetCalled = true
	return s.resetErr
}
func (s *stubAuthHandlerService) Logout(ctx context.Context, jti string, rawRefreshToken string) error {
	s.logoutCalled = true
	return s.logoutErr
}

func TestAuthHandlerLoginRejectsMissingDeviceBindingFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	body, err := json.Marshal(gin.H{
		"username": "user-1",
		"password": "password123",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.Login(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing binding fields, got %d", w.Code)
	}
	if svc.loginCalled {
		t.Fatalf("expected login service not to be called when binding fields are missing")
	}
}

func TestAuthHandlerLoginMapsDeviceBindingErrorsToBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{loginErr: errorx.ErrDeviceKeyInvalid}
	h := handler.NewAuthHandler(svc)

	reqBody := reqdto.LoginRequest{
		Username:           "user-1",
		Password:           "password123",
		DeviceFingerprint:  "install-abc",
		DevicePublicKey:    "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
		DeviceKeyAlgorithm: "ES256",
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.Login(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for device binding error, got %d", w.Code)
	}
	if !svc.loginCalled {
		t.Fatalf("expected login service to be called for valid payload")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("invalid request payload")) {
		t.Fatalf("expected generic bad request response, got %s", w.Body.String())
	}
}

func TestAuthHandlerLoginSetsCookiesOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{
		loginResult: &entity.LoginResult{
			AccessToken:           "access-token",
			RefreshToken:          "refresh-token",
			DeviceID:              "device-1",
			AccessTokenExpiresAt:  time.Now().Add(time.Minute),
			RefreshTokenExpiresAt: time.Now().Add(2 * time.Minute),
		},
	}
	h := handler.NewAuthHandler(svc)

	reqBody := reqdto.LoginRequest{
		Username:           "user-1",
		Password:           "password123",
		DeviceFingerprint:  "install-abc",
		DevicePublicKey:    "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
		DeviceKeyAlgorithm: "ES256",
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.Login(c)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for successful login, got %d", w.Code)
	}
	if !svc.loginCalled {
		t.Fatalf("expected login service to be called")
	}
	if len(bytes.TrimSpace(w.Body.Bytes())) != 0 {
		t.Fatalf("expected empty body for cookie-only login, got %s", w.Body.String())
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

func TestAuthHandlerWhoAmIReturnsFlatSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{
		whoAmIResult: &entity.WhoAmI{
			UserID:      "user-1",
			Username:    "user-1",
			Email:       "user@example.com",
			Phone:       "123456789",
			FullName:    "User One",
			Status:      "active",
			OnBoarding:  false,
			Roles:       []string{"admin"},
			Permissions: []string{"iam:users:read"},
		},
	}
	h := handler.NewAuthHandler(svc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	c.Request = req
	c.Set("user_id", "user-1")
	c.Set("device_id", "device-1")

	h.WhoAmI(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for whoami, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"user_id"`)) {
		t.Fatalf("expected user_id in whoami response, got %s", w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"full_name"`)) {
		t.Fatalf("expected full_name in whoami response, got %s", w.Body.String())
	}
}

func TestAuthHandlerAdminLoginSetsSessionAndDeviceCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	adminSvc := &stubAdminAuthHandlerService{}
	h := handler.NewAuthHandlerWithAdmin(svc, adminSvc)

	body, err := json.Marshal(gin.H{
		"admin_key":       "admin-api-key-1",
		"two_factor_code": "123456",
		"trust_device":    true,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.AdminLogin(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for successful admin login, got %d", w.Code)
	}
	if !adminSvc.loginCalled {
		t.Fatalf("expected admin login service to be called")
	}
	if adminSvc.loginInput.AdminKey != "admin-api-key-1" || adminSvc.loginInput.TwoFactorCode != "123456" || !adminSvc.loginInput.TrustDevice {
		t.Fatalf("unexpected admin login input: %#v", adminSvc.loginInput)
	}

	resp := w.Result()
	defer resp.Body.Close()
	cookies := map[string]*http.Cookie{}
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = cookie
	}
	for _, name := range []string{
		middleware.AdminSessionCookieName,
		middleware.AdminDeviceIDCookieName,
		middleware.AdminDeviceSecretCookieName,
	} {
		cookie := cookies[name]
		if cookie == nil {
			t.Fatalf("expected %s cookie to be set", name)
		}
		if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" {
			t.Fatalf("expected secure HttpOnly host cookie, got %#v", cookie)
		}
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"status":"ok"`)) {
		t.Fatalf("expected ok response, got %s", w.Body.String())
	}
}

func TestAuthHandlerAdminLoginInvalidKeyReturnsUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	adminSvc := &stubAdminAuthHandlerService{loginErr: errorx.ErrAdminAuthInvalid}
	h := handler.NewAuthHandlerWithAdmin(svc, adminSvc)

	body, err := json.Marshal(gin.H{
		"admin_key": "wrong-key",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/admin/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.AdminLogin(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid admin key, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("admin login failed")) {
		t.Fatalf("expected generic unauthorized response, got %s", w.Body.String())
	}
}

func TestAuthHandlerLogoutMissingRefreshCookieReturnsGenericUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	c.Request = req
	c.Set("jti", "jti-1")

	h.Logout(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing refresh cookie, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("unauthorized")) {
		t.Fatalf("expected generic unauthorized response, got %s", w.Body.String())
	}
}

func TestAuthHandlerRegisterSuccessful(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	reqBody := reqdto.RegisterRequest{
		FullName:    "Test User",
		Email:       "test@example.com",
		Username:    "testuser",
		Password:    "password123",
		RePassword:  "password123",
		PhoneNumber: stringPtr("123456789"),
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.Register(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for successful registration, got %d: %s", w.Code, w.Body.String())
	}
	if !svc.registerCalled {
		t.Fatalf("expected register service to be called")
	}
}

func TestAuthHandlerRegisterConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{registerErr: errorx.ErrUsernameAlreadyExists}
	h := handler.NewAuthHandler(svc)

	reqBody := reqdto.RegisterRequest{
		FullName:    "Test User",
		Email:       "test@example.com",
		Username:    "testuser",
		Password:    "password123",
		RePassword:  "password123",
		PhoneNumber: stringPtr("123456789"),
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.Register(c)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for existing account, got %d", w.Code)
	}
}

func TestAuthHandlerRegisterValidationErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	tests := []struct {
		name string
		req  reqdto.RegisterRequest
	}{
		{"empty name", reqdto.RegisterRequest{FullName: "", Email: "a@b.com", Username: "user", Password: "p", RePassword: "p"}},
		{"invalid username", reqdto.RegisterRequest{FullName: "User", Email: "a@b.com", Username: "USER!", Password: "p", RePassword: "p"}},
		{"password mismatch", reqdto.RegisterRequest{FullName: "User", Email: "a@b.com", Username: "user", Password: "p1", RePassword: "p2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			h.Register(c)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d", tt.name, w.Code)
			}
		})
	}
}

func TestAuthHandlerActivateMissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/activate", nil)
	c.Request = req

	h.Activate(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing token, got %d", w.Code)
	}
}

func TestAuthHandlerActivateSuccessful(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/activate?token=valid-token", nil)
	c.Request = req

	h.Activate(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for successful activation, got %d", w.Code)
	}
	if !svc.activateCalled {
		t.Fatalf("expected activate service to be called")
	}
}

func TestAuthHandlerActivateInvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{activateErr: errorx.ErrActivationTokenInvalid}
	h := handler.NewAuthHandler(svc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/activate?token=invalid-token", nil)
	c.Request = req

	h.Activate(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid token, got %d", w.Code)
	}
}

func TestAuthHandlerLoginPendingAccountResendsEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{
		loginResult: &entity.LoginResult{Pending: true},
	}
	h := handler.NewAuthHandler(svc)

	reqBody := reqdto.LoginRequest{
		Username:          "user-1",
		Password:          "password123",
		DeviceFingerprint: "install-abc",
		DevicePublicKey:   "pubkey",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.Login(c)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for pending account, got %d", w.Code)
	}
}

func TestAuthHandlerLoginMFARequired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{
		loginResult: &entity.LoginResult{
			MFARequired:         true,
			MFAChallengeID:      "challenge-1",
			MFAAvailableMethods: []string{"totp"},
		},
	}
	h := handler.NewAuthHandler(svc)

	reqBody := reqdto.LoginRequest{
		Username:          "user-1",
		Password:          "password123",
		DeviceFingerprint: "install-abc",
		DevicePublicKey:   "pubkey",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.Login(c)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for MFA required, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"mfa_required":true`)) {
		t.Fatalf("expected mfa_required in response, got %s", w.Body.String())
	}
}

func TestAuthHandlerLoginErrorMappings(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()

	tests := []struct {
		err  error
		code int
	}{
		{errorx.ErrUserInactive, http.StatusForbidden},
		{errorx.ErrInvalidCredentials, http.StatusUnauthorized},
		{errorx.ErrDeviceBindingRequired, http.StatusBadRequest},
		{errors.New("generic"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			svc := &stubAuthHandlerService{loginErr: tt.err}
			h := handler.NewAuthHandler(svc)
			reqBody := reqdto.LoginRequest{
				Username:          "u",
				Password:          "p",
				DeviceFingerprint: "f",
				DevicePublicKey:   "k",
			}
			body, _ := json.Marshal(reqBody)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			h.Login(c)

			if w.Code != tt.code {
				t.Fatalf("expected %d for %v, got %d", tt.code, tt.err, w.Code)
			}
		})
	}
}

func TestAuthHandlerForgotPasswordAlwaysAccepted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	reqBody := reqdto.ForgotPasswordRequest{Email: "test@example.com"}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.ForgotPassword(c)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for forgot password, got %d", w.Code)
	}
	if !svc.forgotCalled {
		t.Fatalf("expected forgot password service to be called")
	}
}

func TestAuthHandlerResetPasswordSuccessful(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	reqBody := reqdto.ResetPasswordRequest{
		NewPassword: "newpassword123",
		RePassword:  "newpassword123",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/reset-password?token=valid-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.ResetPassword(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for successful reset, got %d", w.Code)
	}
	if !svc.resetCalled {
		t.Fatalf("expected reset password service to be called")
	}
}

func TestAuthHandlerResetPasswordValidationErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	t.Run("password mismatch", func(t *testing.T) {
		reqBody := reqdto.ResetPasswordRequest{NewPassword: "p1", RePassword: "p2"}
		body, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/reset-password?token=t", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req
		h.ResetPassword(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("missing token", func(t *testing.T) {
		reqBody := reqdto.ResetPasswordRequest{NewPassword: "p", RePassword: "p"}
		body, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req
		h.ResetPassword(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})
}

func TestAuthHandlerWhoAmIErrorMappings(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()

	tests := []struct {
		err  error
		code int
	}{
		{errorx.ErrUserNotFound, http.StatusUnauthorized},
		{errors.New("generic"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			svc := &stubAuthHandlerService{whoAmIErr: tt.err}
			h := handler.NewAuthHandler(svc)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req, _ := http.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
			c.Request = req
			c.Set("user_id", "u")
			c.Set("device_id", "d")

			h.WhoAmI(c)

			if w.Code != tt.code {
				t.Fatalf("expected %d for %v, got %d", tt.code, tt.err, w.Code)
			}
		})
	}
}

func TestAuthHandlerLogoutSuccessful(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubAuthHandlerService{}
	h := handler.NewAuthHandler(svc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "token-123"})
	c.Request = req
	c.Set(middleware.CtxKeyJTI, "jti-1")

	h.Logout(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for successful logout, got %d", w.Code)
	}
	if !svc.logoutCalled {
		t.Fatalf("expected logout service to be called")
	}
}

func stringPtr(s string) *string { return &s }
