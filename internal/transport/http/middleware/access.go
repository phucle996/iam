package middleware

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"controlplane/internal/security"
	"controlplane/pkg/apires"
	"controlplane/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// Context keys injected by the Access middleware.
// Use these constants in handlers instead of string literals.
const (
	jwtClaimsContextKey = "jwt_claims" // full security.Claims object

	CtxKeyUserID   = "user_id"   // string — JWT subject
	CtxKeyRole     = "role"      // string — user role
	CtxKeyJTI      = "jti"       // string — token ID
	CtxKeyStatus   = "status"    // string — account status
	CtxKeyLevel    = "level"     // int    — security level (0=highest)
	CtxKeyTenant   = "tenant"    // string — tenant ID
	CtxKeyDeviceID = "device_id" // string — device ID
)

// Access checks for a valid JWT in Authorization header or cookie.
// On success, injects identity claims and adds user_id to logger context.
func Access(sp security.SecretProvider, rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := security.ExtractBearerToken(c.GetHeader("Authorization"))
		if !ok {
			cookieToken, err := c.Cookie("access_token")
			if err != nil || strings.TrimSpace(cookieToken) == "" {
				c.Header("WWW-Authenticate", "Bearer")
				apires.RespondUnauthorized(c, "unauthorized")
				c.Abort()
				return
			}
			token = cookieToken
		}

		if sp == nil {
			apires.RespondServiceUnavailable(c, "authentication temporarily unavailable")
			c.Abort()
			return
		}

		candidates, err := sp.GetCandidates(security.SecretFamilyAccess)
		if err != nil || len(candidates) == 0 {
			apires.RespondServiceUnavailable(c, "authentication temporarily unavailable")
			c.Abort()
			return
		}

		var (
			claims      security.Claims
			parsed      bool
			parseErr    error
			emptySecret bool
		)
		for _, candidate := range candidates {
			claims, parseErr = security.Parse(token, candidate.Value)
			if parseErr == nil {
				parsed = true
				break
			}
			if errors.Is(parseErr, security.ErrEmptySecret) {
				emptySecret = true
			}
		}
		if !parsed {
			if emptySecret {
				apires.RespondServiceUnavailable(c, "authentication temporarily unavailable")
				c.Abort()
				return
			}
			c.Header("WWW-Authenticate", "Bearer")
			apires.RespondUnauthorized(c, "unauthorized")
			c.Abort()
			return
		}

		blacklisted, blacklistErr := IsBlacklisted(c.Request.Context(), rdb, claims.TokenID)
		if blacklistErr != nil {
			logger.HandlerWarn(c, "iam.access", blacklistErr, "redis blacklist check failed")
			apires.RespondServiceUnavailable(c, "authentication temporarily unavailable")
			c.Abort()
			return
		}
		if blacklisted {
			logger.HandlerWarn(c, "iam.access", nil, "token is blacklisted")
			c.Header("WWW-Authenticate", "Bearer")
			apires.RespondUnauthorized(c, "token has been revoked")
			c.Abort()
			return
		}

		// Store full claims for callers that need everything.
		c.Set(jwtClaimsContextKey, claims)

		// Inject individual identity fields as flat keys.
		c.Set(CtxKeyUserID, claims.Subject)
		c.Set(CtxKeyRole, claims.Role)
		c.Set(CtxKeyJTI, claims.TokenID)
		c.Set(CtxKeyStatus, claims.Status)
		c.Set(CtxKeyLevel, claims.Level) // int — read directly by RequireLevel
		c.Set(CtxKeyDeviceID, claims.DeviceID)
		c.Set(CtxKeyTenant, claims.TenantID)

		// Piggyback on logger key so request logs include user_id automatically.
		if claims.Subject != "" {
			c.Set(logger.KeyUserID, claims.Subject)
		}

		c.Next()
	}
}

func GetUserID(c *gin.Context) string {
	v, ok := c.Get(CtxKeyUserID)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func GetDeviceID(c *gin.Context) string {
	v, ok := c.Get(CtxKeyDeviceID)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// IsBlacklisted checks if the JTI is blacklisted in Redis.
func IsBlacklisted(ctx context.Context, rdb *redis.Client, jti string) (bool, error) {
	if jti == "" || rdb == nil {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	checkCtx, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
	defer cancel()

	key := fmt.Sprintf("iam:blacklist:%s", jti)
	exists, err := rdb.Exists(checkCtx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}
