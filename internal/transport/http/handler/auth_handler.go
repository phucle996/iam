package handler

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"iam/internal/domain/entity"
	domainsvc "iam/internal/domain/service"
	"iam/internal/observability"
	"iam/internal/transport/http/middleware"
	iam_reqdto "iam/internal/transport/http/request"
	iam_resdto "iam/internal/transport/http/response"

	response "iam/pkg/apires"
	"iam/pkg/errorx"
	"iam/pkg/logger"

	"github.com/gin-gonic/gin"
)

var (
	registerUsernamePattern = regexp.MustCompile(`^[a-z0-9._-]+$`)
	whoamiRolesPool         sync.Pool
	whoamiPermsPool         sync.Pool
)

const (
	iamPooledSliceDefaultCap = 8
	iamPooledSliceMaxCap     = 256
)

type AuthHandler struct {
	authSvc      domainsvc.AuthService
	adminAuthSvc domainsvc.AdminAuthService
}

func NewAuthHandler(authSvc domainsvc.AuthService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc}
}

func NewAuthHandlerWithAdmin(authSvc domainsvc.AuthService, adminAuthSvc domainsvc.AdminAuthService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, adminAuthSvc: adminAuthSvc}
}

// @Router /api/v1/auth/register [post]
// @Tags Auth
// @Summary Register
// @Description Register
// @Accept json
// @Produce json
// @Success 201 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *AuthHandler) Register(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req iam_reqdto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.auth.register", err, "Failed to bind register payload")
		response.RespondBadRequest(c, "invalid request payload")
		return
	}

	fullName := strings.TrimSpace(req.FullName)
	email := strings.ToLower(strings.TrimSpace(req.Email))
	username := strings.ToLower(strings.TrimSpace(req.Username))

	if fullName == "" || utf8.RuneCountInString(fullName) < 2 || utf8.RuneCountInString(fullName) > 120 {
		logger.HandlerWarn(c, "iam.auth.register", nil, "invalid full name")
		response.RespondBadRequest(c, "invalid full name")
		return
	}

	if !registerUsernamePattern.MatchString(username) {
		logger.HandlerWarn(c, "iam.auth.register", nil, "invalid username")
		response.RespondBadRequest(c, "invalid username")
		return
	}

	if req.Password != req.RePassword {
		logger.HandlerWarn(c, "iam.auth.register", nil, "password confirmation does not match")
		response.RespondBadRequest(c, "password confirmation does not match")
		return
	}

	phone := ""
	if req.PhoneNumber != nil {
		phone = strings.TrimSpace(*req.PhoneNumber)
	}

	user := &entity.User{
		Username:      username,
		Email:         email,
		Phone:         phone,
		PasswordHash:  "",
		SecurityLevel: 4,
		Status:        "pending",
		StatusReason:  "pending_email_verification",
		Role:          "",
	}
	profile := &entity.UserProfile{
		Fullname: fullName,
		Timezone: "UTC",
	}

	if err := h.authSvc.Register(ctx, user, profile, req.Password); err != nil {
		logger.HandlerError(c, "iam.auth.register", err)
		switch {
		case errors.Is(err, errorx.ErrUsernameAlreadyExists),
			errors.Is(err, errorx.ErrEmailAlreadyExists),
			errors.Is(err, errorx.ErrPhoneAlreadyExists):
			response.RespondConflict(c, "account already exists")
		default:
			response.RespondInternalError(c, "an unexpected error occurred during registration")
		}
		return
	}

	logger.HandlerInfo(c, "iam.auth.register", "Account registered successfully")
	response.RespondCreated(c, nil, "Account registered successfully. Please verify your email.")
}

// @Router /api/v1/auth/activate [post]
// @Tags Auth
// @Summary Activate
// @Description Activate
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *AuthHandler) Activate(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	token := strings.TrimSpace(c.Query("token"))
	if token == "" {
		logger.HandlerWarn(c, "iam.auth.activate", nil, "Missing activation token")
		response.RespondBadRequest(c, "invalid activation token")
		return
	}

	if err := h.authSvc.Activate(ctx, token); err != nil {
		logger.HandlerError(c, "iam.auth.activate", err)
		switch {
		case errors.Is(err, errorx.ErrActivationTokenInvalid):
			response.RespondBadRequest(c, "invalid activation token")
		case errors.Is(err, errorx.ErrActivationTokenExpired):
			response.RespondBadRequest(c, "activation token expired")
		case errors.Is(err, errorx.ErrUserNotFound):
			response.RespondBadRequest(c, "invalid activation token")
		default:
			response.RespondInternalError(c, "an unexpected error occurred during activation")
		}
		return
	}

	logger.HandlerInfo(c, "iam.auth.activate", "Account activated successfully")
	response.RespondSuccess(c, nil, "account activated successfully")
}

// @Router /api/v1/auth/login [post]
// @Tags Auth
// @Summary Login
// @Description Login
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *AuthHandler) Login(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	loginSuccess := false
	defer func() {
		if prom := observability.CurrentPrometheus(); prom != nil {
			prom.ObserveAuthAttempt("login", loginSuccess)
		}
	}()

	var req iam_reqdto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.auth", err, "Failed to bind request payload")
		response.RespondBadRequest(c, "invalid request payload")
		return
	}

	username := strings.ToLower(strings.TrimSpace(req.Username))
	password := strings.TrimSpace(req.Password)
	deviceFingerprint := strings.TrimSpace(req.DeviceFingerprint)
	devicePublicKey := strings.TrimSpace(req.DevicePublicKey)
	deviceKeyAlgorithm := strings.TrimSpace(req.DeviceKeyAlgorithm)

	if deviceFingerprint == "" || devicePublicKey == "" {
		logger.HandlerWarn(c, "iam.auth", nil, "device binding fields are required")
		response.RespondBadRequest(c, "invalid request payload")
		return
	}
	if deviceKeyAlgorithm == "" {
		deviceKeyAlgorithm = "ES256"
	}

	result, err := h.authSvc.Login(ctx, username, password, deviceFingerprint, devicePublicKey, deviceKeyAlgorithm)
	if err != nil {
		logger.HandlerError(c, "iam.auth", err)

		if errors.Is(err, errorx.ErrUserInactive) {
			response.RespondForbidden(c, "account is inactive")
			return
		}

		if errors.Is(err, errorx.ErrInvalidCredentials) || errors.Is(err, errorx.ErrUserNotFound) {
			response.RespondUnauthorized(c, "invalid username or password")
			return
		}

		if errors.Is(err, errorx.ErrDeviceBindingRequired) || errors.Is(err, errorx.ErrDeviceKeyInvalid) {
			response.RespondBadRequest(c, "invalid request payload")
			return
		}

		response.RespondInternalError(c, "an unexpected error occurred during login")
		return
	}

	if result != nil && result.Pending {
		loginSuccess = true
		logger.HandlerInfo(c, "iam.auth", "Pending account activation email resent")
		response.RespondAccepted(c, nil, "account is pending activation, verification email resent")
		return
	}

	// MFA gate — client must complete MFA before receiving tokens.
	if result != nil && result.MFARequired {
		logger.HandlerInfo(c, "iam.auth", "MFA required — challenge issued")
		response.RespondAccepted(c, gin.H{
			"mfa_required":      true,
			"challenge_id":      result.MFAChallengeID,
			"available_methods": result.MFAAvailableMethods,
		}, "mfa verification required")
		return
	}

	if result == nil {
		logger.HandlerError(c, "iam.auth", err)
		response.RespondInternalError(c, "an unexpected error occurred during login")
		return
	}

	setSessionCookies(c, result.AccessToken, result.RefreshToken, result.DeviceID, result.AccessTokenExpiresAt, result.RefreshTokenExpiresAt)
	loginSuccess = true

	logger.HandlerInfo(c, "iam.auth", "User logged in successfully")
	c.AbortWithStatus(http.StatusNoContent)
}

// @Router /admin/auth/login [post]
// @Tags Auth
// @Summary Admin login with API key, 2FA, CIDR, and device binding
// @Description Creates a server-side admin session and bound device cookies.
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
func (h *AuthHandler) AdminLogin(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	adminSuccess := false
	defer func() {
		if prom := observability.CurrentPrometheus(); prom != nil {
			prom.ObserveAuthAttempt("admin_login", adminSuccess)
		}
	}()

	var req iam_reqdto.AdminLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.auth.admin-login", err, "invalid payload")
		response.RespondBadRequest(c, "invalid request payload")
		return
	}

	if h.adminAuthSvc == nil {
		response.RespondServiceUnavailable(c, "admin authentication unavailable")
		return
	}

	adminKey := strings.TrimSpace(req.AdminKey)
	if adminKey == "" {
		response.RespondBadRequest(c, "invalid request payload")
		return
	}

	deviceID, _ := c.Cookie(middleware.AdminDeviceIDCookieName)
	deviceSecret, _ := c.Cookie(middleware.AdminDeviceSecretCookieName)

	result, err := h.adminAuthSvc.Login(ctx, entity.AdminLoginInput{
		AdminKey:      adminKey,
		TwoFactorCode: strings.TrimSpace(req.TwoFactorCode),
		TrustDevice:   req.TrustDevice,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
		DeviceID:      strings.TrimSpace(deviceID),
		DeviceSecret:  strings.TrimSpace(deviceSecret),
	})
	if err != nil {
		logger.HandlerError(c, "iam.auth.admin-login", err)
		switch {
		case errors.Is(err, errorx.ErrAdminDeviceInvalid):
			clearAdminAuthCookies(c)
			response.RespondUnauthorized(c, "admin login failed")
		case errors.Is(err, errorx.ErrAdminAuthInvalid),
			errors.Is(err, errorx.ErrAdminSessionInvalid):
			response.RespondUnauthorized(c, "admin login failed")
		default:
			response.RespondInternalError(c, "admin login failed")
		}
		return
	}
	if result == nil || result.Admin == nil {
		response.RespondInternalError(c, "admin login failed")
		return
	}

	setAdminSessionCookies(c, result)
	adminSuccess = true
	logger.HandlerInfo(c, "iam.auth.admin-login", "admin login successful")
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"admin": gin.H{
			"id":           result.Admin.ID,
			"display_name": result.Admin.DisplayName,
		},
		"session": gin.H{
			"expires_at": result.SessionExpiresAt,
		},
	})
}

// @Router /admin/auth/logout [post]
// @Tags Auth
// @Summary Admin logout
// @Description Revokes the server-side admin session and clears the session cookie.
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
func (h *AuthHandler) AdminLogout(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	sessionToken, _ := c.Cookie(middleware.AdminSessionCookieName)
	if h.adminAuthSvc != nil {
		if err := h.adminAuthSvc.Logout(ctx, sessionToken); err != nil {
			logger.HandlerError(c, "iam.auth.admin-logout", err)
		}
	}

	clearAdminSessionCookie(c)
	logger.HandlerInfo(c, "iam.auth.admin-logout", "admin logged out")
	response.RespondSuccess(c, nil, "logged out successfully")
}

// @Router /admin/auth/session [get]
// @Tags Auth
// @Summary Admin session bootstrap
// @Description Returns the active admin session context.
// @Produce json
// @Success 200 {object} response.Response
func (h *AuthHandler) AdminSession(c *gin.Context) {
	adminID := strings.TrimSpace(middleware.GetAdminUserID(c))
	if adminID == "" {
		response.RespondUnauthorized(c, "unauthorized")
		return
	}

	displayName, _ := c.Get(middleware.CtxKeyAdminDisplayName)
	sessionID, _ := c.Get(middleware.CtxKeyAdminSessionID)
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"admin": gin.H{
			"id":           adminID,
			"display_name": displayName,
		},
		"session": gin.H{
			"id": sessionID,
		},
	})
}

// @Router /api/v1/auth/forgot-password [post]
// @Tags Auth
// @Summary Forgot password
// @Description Forgot password
// @Accept json
// @Produce json
// @Success 202 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	forgotSuccess := false
	defer func() {
		if prom := observability.CurrentPrometheus(); prom != nil {
			prom.ObserveAuthAttempt("forgot_password", forgotSuccess)
		}
	}()

	var req iam_reqdto.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.auth.forgot-password", err, "invalid payload")
		response.RespondBadRequest(c, "invalid request payload")
		return
	}

	// Always respond 202 — prevent enumeration of valid email addresses.
	if err := h.authSvc.ForgotPassword(ctx, req.Email); err != nil {
		logger.HandlerError(c, "iam.auth.forgot-password", err)
		// Do NOT expose to client.
	}

	logger.HandlerInfo(c, "iam.auth.forgot-password", "forgot-password requested")
	forgotSuccess = true
	response.RespondAccepted(c, nil, "if the email is registered, a reset link has been sent")
}

// @Router /api/v1/auth/reset-password [post]
// @Tags Auth
// @Summary Reset password
// @Description Reset password
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	resetSuccess := false
	defer func() {
		if prom := observability.CurrentPrometheus(); prom != nil {
			prom.ObserveAuthAttempt("reset_password", resetSuccess)
		}
	}()

	var req iam_reqdto.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.auth.reset-password", err, "invalid payload")
		response.RespondBadRequest(c, "invalid request payload")
		return
	}

	if req.NewPassword != req.RePassword {
		response.RespondBadRequest(c, "passwords do not match")
		return
	}

	token := c.Query("token")
	if token == "" {
		logger.HandlerWarn(c, "iam.auth.reset-password", nil, "invalid token")
		response.RespondBadRequest(c, "invalid token")
		return
	}

	if err := h.authSvc.ResetPassword(ctx, token, req.NewPassword); err != nil {
		logger.HandlerError(c, "iam.auth.reset-password", err)
		switch {
		case errors.Is(err, errorx.ErrResetTokenInvalid):
			response.RespondBadRequest(c, "reset token is invalid")
		case errors.Is(err, errorx.ErrResetTokenExpired):
			response.RespondBadRequest(c, "reset token has expired")
		case errors.Is(err, errorx.ErrWeakPassword):
			response.RespondBadRequest(c, "password does not meet requirements")
		default:
			response.RespondInternalError(c, "password reset failed")
		}
		return
	}

	logger.HandlerInfo(c, "iam.auth.reset-password", "password reset successful")
	resetSuccess = true
	response.RespondSuccess(c, nil, "password reset successful")
}

// @Router /api/v1/auth/logout [post]
// @Tags Auth
// @Summary Logout
// @Description Logout
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
func (h *AuthHandler) Logout(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// 1. Get JTI from the gin context (injected by Access middleware)
	jti := c.GetString(middleware.CtxKeyJTI)

	// 2. Get refresh token from cookie
	refreshTokenCookie, err := c.Cookie("refresh_token")
	if err != nil || refreshTokenCookie == "" {
		logger.HandlerWarn(c, "iam.auth.logout", err, "refresh token cookie not found")
		response.RespondUnauthorized(c, "unauthorized")
		return
	}

	// 3. Blacklist access token and revoke refresh token
	if err := h.authSvc.Logout(ctx, jti, refreshTokenCookie); err != nil {
		logger.HandlerError(c, "iam.auth.logout", err)
	}

	// 4. Clear cookies on client
	clearSessionCookies(c)

	logger.HandlerInfo(c, "iam.auth.logout", "user logged out successfully")
	response.RespondSuccess(c, nil, "logged out successfully")
}

// @Router /api/v1/whoami [get]
// @Tags Auth
// @Summary Who am I
// @Description Return authenticated session snapshot
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
func (h *AuthHandler) WhoAmI(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := strings.TrimSpace(middleware.GetUserID(c))
	deviceID := strings.TrimSpace(middleware.GetDeviceID(c))
	if userID == "" || deviceID == "" {
		response.RespondUnauthorized(c, "unauthorized")
		return
	}

	result, err := h.authSvc.WhoAmI(ctx, userID)
	if err != nil {
		logger.HandlerError(c, "iam.auth.whoami", err)
		switch {
		case errors.Is(err, errorx.ErrUserNotFound),
			errors.Is(err, errorx.ErrProfileNotFound),
			errors.Is(err, errorx.ErrRoleNotFound):
			response.RespondUnauthorized(c, "unauthorized")
		default:
			response.RespondInternalError(c, "failed to load session")
		}
		return
	}

	logger.HandlerInfo(c, "iam.auth.whoami", "session snapshot loaded")

	// Reuse small string-slice buffers on the hot /whoami path.
	borrowStringSlice := func(pool *sync.Pool, minCap int) []string {
		if minCap < iamPooledSliceDefaultCap {
			minCap = iamPooledSliceDefaultCap
		}
		if pooled, ok := pool.Get().([]string); ok && cap(pooled) >= minCap {
			return pooled[:0]
		}
		return make([]string, 0, minCap)
	}
	releaseStringSlice := func(pool *sync.Pool, items []string) {
		if cap(items) == 0 || cap(items) > iamPooledSliceMaxCap {
			return
		}
		full := items[:cap(items)]
		clear(full)
		pool.Put(full[:0])
	}

	roles := borrowStringSlice(&whoamiRolesPool, len(result.Roles))
	roles = append(roles, result.Roles...)
	defer releaseStringSlice(&whoamiRolesPool, roles)

	permissions := borrowStringSlice(&whoamiPermsPool, len(result.Permissions))
	permissions = append(permissions, result.Permissions...)
	defer releaseStringSlice(&whoamiPermsPool, permissions)

	response.RespondSuccess(c, iam_resdto.WhoamiResponse{
		UserID:         result.UserID,
		Username:       result.Username,
		Email:          result.Email,
		Phone:          result.Phone,
		FullName:       result.FullName,
		Company:        result.Company,
		ReferralSource: result.ReferralSource,
		JobFunction:    result.JobFunction,
		Country:        result.Country,
		AvatarURL:      result.AvatarURL,
		Bio:            result.Bio,
		Status:         result.Status,
		OnBoarding:     result.OnBoarding,
		Roles:          roles,
		Permissions:    permissions,
	}, "whoami")
}
