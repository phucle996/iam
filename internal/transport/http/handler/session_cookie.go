package handler

import (
	"net/http"
	"strings"
	"time"

	"iam/internal/domain/entity"
	"iam/internal/security"
	"iam/internal/transport/http/middleware"

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

func setAdminAPITokenCookie(c *gin.Context, apiToken string) {
	secureCookie := isSecureCookie(c)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "apitoken",
		Value:    apiToken,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}

func setAdminSessionCookies(c *gin.Context, result *entity.AdminLoginResult) {
	if result == nil {
		return
	}
	sessionMaxAge := cookieMaxAge(result.SessionExpiresAt)
	deviceMaxAge := cookieMaxAge(result.DeviceExpiresAt)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     middleware.AdminSessionCookieName,
		Value:    result.SessionToken,
		Path:     "/",
		MaxAge:   sessionMaxAge,
		Expires:  result.SessionExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     middleware.AdminDeviceIDCookieName,
		Value:    result.DeviceID,
		Path:     "/",
		MaxAge:   deviceMaxAge,
		Expires:  result.DeviceExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     middleware.AdminDeviceSecretCookieName,
		Value:    result.DeviceSecret,
		Path:     "/",
		MaxAge:   deviceMaxAge,
		Expires:  result.DeviceExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearAdminSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     middleware.AdminSessionCookieName,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearAdminAuthCookies(c *gin.Context) {
	for _, name := range []string{
		middleware.AdminSessionCookieName,
		middleware.AdminDeviceIDCookieName,
		middleware.AdminDeviceSecretCookieName,
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
