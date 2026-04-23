package handler

import (
	"net/http"
	"os"
	"strings"
	"time"

	"controlplane/internal/security"

	"github.com/gin-gonic/gin"
)

func setSessionCookies(c *gin.Context, accessToken, refreshToken, deviceID string, accessExpiresAt, refreshExpiresAt time.Time) {
	secureCookie := isSecureCookie(c)
	accessMaxAge := cookieMaxAge(accessExpiresAt)
	refreshMaxAge := cookieMaxAge(refreshExpiresAt)
	refreshHash := security.HashRefreshToken(refreshToken)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		MaxAge:   accessMaxAge,
		Expires:  accessExpiresAt,
		HttpOnly: true,
		Secure:   secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   refreshMaxAge,
		Expires:  refreshExpiresAt,
		HttpOnly: true,
		Secure:   secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "device_id",
		Value:    deviceID,
		Path:     "/",
		MaxAge:   refreshMaxAge,
		Expires:  refreshExpiresAt,
		HttpOnly: false,
		Secure:   secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token_hash",
		Value:    refreshHash,
		Path:     "/",
		MaxAge:   refreshMaxAge,
		Expires:  refreshExpiresAt,
		HttpOnly: false,
		Secure:   secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func setAdminAPITokenCookie(c *gin.Context, apiToken string, expiresAt time.Time) {
	secureCookie := isSecureCookie(c)
	maxAge := cookieMaxAge(expiresAt)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "apitoken",
		Value:    apiToken,
		Path:     "/admin",
		MaxAge:   maxAge,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}

func adminAPITokenExpiryFromNow() time.Time {
	ttl := 15 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("SECURITY_ADMIN_API_TOKEN_TTL")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			ttl = parsed
		}
	}
	return time.Now().UTC().Add(ttl)
}

func clearSessionCookies(c *gin.Context) {
	secureCookie := isSecureCookie(c)
	for _, cookie := range []http.Cookie{
		{
			Name:     "access_token",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   secureCookie,
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     "refresh_token",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   secureCookie,
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     "device_id",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: false,
			Secure:   secureCookie,
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     "refresh_token_hash",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: false,
			Secure:   secureCookie,
			SameSite: http.SameSiteLaxMode,
		},
	} {
		http.SetCookie(c.Writer, &cookie)
	}
}

func cookieMaxAge(expiresAt time.Time) int {
	if expiresAt.IsZero() {
		return 0
	}

	seconds := int(time.Until(expiresAt).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
}

func isSecureCookie(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}

	if c.Request.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")), "https")
}
