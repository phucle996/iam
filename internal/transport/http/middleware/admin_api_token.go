package middleware

import (
	"context"

	"iam/internal/domain/entity"
	"iam/pkg/apires"
	"iam/pkg/logger"

	"github.com/gin-gonic/gin"
)

const adminAPITokenCookieName = "apitoken"

// AdminAPIToken validates the admin API token stored in cookie.
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

		c.Next()
	}
}
