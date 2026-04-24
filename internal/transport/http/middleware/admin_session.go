package middleware

import (
	"context"
	"errors"
	"net/http"

	"iam/internal/domain/entity"
	"iam/pkg/apires"
	"iam/pkg/errorx"
	"iam/pkg/logger"

	"github.com/gin-gonic/gin"
)

const (
	AdminSessionCookieName      = "__Host-aurora_admin_session"
	AdminDeviceIDCookieName     = "__Host-aurora_admin_device_id"
	AdminDeviceSecretCookieName = "__Host-aurora_admin_device_secret"

	CtxKeyAdminUserID      = "admin_user_id"
	CtxKeyAdminDisplayName = "admin_display_name"
	CtxKeyAdminCredential  = "admin_credential_id"
	CtxKeyAdminSessionID   = "admin_session_id"
)

func AdminSession(authorize func(ctx context.Context, input entity.AdminSessionAuthInput) (*entity.AdminSessionContext, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		if authorize == nil {
			apires.RespondServiceUnavailable(c, "admin authentication unavailable")
			c.Abort()
			return
		}

		sessionToken, err := c.Cookie(AdminSessionCookieName)
		if err != nil || sessionToken == "" {
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}
		deviceID, err := c.Cookie(AdminDeviceIDCookieName)
		if err != nil || deviceID == "" {
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}
		deviceSecret, err := c.Cookie(AdminDeviceSecretCookieName)
		if err != nil || deviceSecret == "" {
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}

		authCtx, err := authorize(c.Request.Context(), entity.AdminSessionAuthInput{
			SessionToken: sessionToken,
			DeviceID:     deviceID,
			DeviceSecret: deviceSecret,
			ClientIP:     c.ClientIP(),
			UserAgent:    c.Request.UserAgent(),
		})
		if err != nil || authCtx == nil {
			logger.HandlerWarn(c, "admin.session", err, "admin session rejected")
			if errors.Is(err, errorx.ErrAdminDeviceInvalid) {
				clearAdminAuthCookies(c)
			}
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}

		c.Set(CtxKeyAdminUserID, authCtx.AdminUserID)
		c.Set(CtxKeyAdminDisplayName, authCtx.DisplayName)
		c.Set(CtxKeyAdminCredential, authCtx.CredentialID)
		c.Set(CtxKeyDeviceID, authCtx.DeviceID)
		c.Set(CtxKeyAdminSessionID, authCtx.SessionID)
		if authCtx.AdminUserID != "" {
			c.Set(logger.KeyUserID, authCtx.AdminUserID)
		}

		c.Next()
	}
}

func GetAdminUserID(c *gin.Context) string {
	v, ok := c.Get(CtxKeyAdminUserID)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func clearAdminAuthCookies(c *gin.Context) {
	for _, name := range []string{
		AdminSessionCookieName,
		AdminDeviceIDCookieName,
		AdminDeviceSecretCookieName,
	} {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     name,
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
}
