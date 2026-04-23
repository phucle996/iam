package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"controlplane/internal/domain/entity"
	"controlplane/pkg/apires"
	"controlplane/pkg/logger"

	"github.com/gin-gonic/gin"
)

const adminAPITokenCookieName = "apitoken"

// AdminAPIToken validates and rotates the admin API token stored in cookie.
func AdminAPIToken(authorize func(ctx context.Context, token string) (*entity.AdminAPIAuthorization, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		if authorize == nil {
			apires.RespondServiceUnavailable(c, "admin token validator unavailable")
			c.Abort()
			return
		}

		token, err := c.Cookie(adminAPITokenCookieName)
		if err != nil {
			logger.HandlerWarn(c, "admin.api-token", err, "admin api token cookie not found")
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}

		authz, err := authorize(c.Request.Context(), token)
		if err != nil {
			logger.HandlerError(c, "admin.api-token", err)
			apires.RespondServiceUnavailable(c, "admin api token validation unavailable")
			c.Abort()
			return
		}
		if authz == nil || !authz.Valid {
			logger.HandlerWarn(c, "admin.api-token", nil, "invalid admin api token")
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}

		if authz.CookieToken != "" {
			setAdminAPITokenCookie(c, authz.CookieToken, authz.ExpiresAt)
		}

		c.Next()
	}
}

func setAdminAPITokenCookie(c *gin.Context, token string, expiresAt time.Time) {
	if c == nil || c.Request == nil || c.Writer == nil {
		return
	}

	secureCookie := c.Request.TLS != nil || strings.EqualFold(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")), "https")
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     adminAPITokenCookieName,
		Value:    token,
		Path:     "/admin",
		MaxAge:   maxAge,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}
