package app

import (
	"iam/internal/config"
	"iam/internal/transport/http/middleware"
	"time"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes registers HTTP routes for the IAM module.
//
// Level matrix (lower number = higher privilege):
//
//	0   super-admin
//	1  admin global
//	2  admin tenant
//	3 	other roles special in the tenant : manager ,... .
//
// the admin can define level user in these tenant ( 3 and lower)
//
//	4 	 authenticate user global or user level default in the tenant
//
// (when user just join tenant)
func RegisterRoutes(router *gin.Engine, cfg *config.Config, m *Module) {

	// ----------------------------
	// Health endpoints
	// ----------------------------
	router.GET("/api/v1/health/liveness", m.HealthHandler.Liveness)
	router.GET("/api/v1/health/readiness", m.HealthHandler.Readiness)
	router.GET("/api/v1/health/startup", m.HealthHandler.Startup)

	// ----------------------------
	// Global authentication routes
	// ----------------------------

	// đăng kí tài khoản global (không thuộc tenant nào)
	router.POST(
		"/api/v1/auth/register",
		middleware.RateLimit(m.RateLimiter, "auth_register", 10, 5, time.Minute),
	)

	// kích hoạt tài khoản global (không thuộc tenant nào)
	router.GET("/api/v1/auth/activate",
		middleware.RateLimit(m.RateLimiter, "auth_activate", 10, 5, time.Minute),
		m.AuthHandler.Activate,
	)

	// đăng nhập tài khoản global (không thuộc tenant nào)
	router.POST(
		"/api/v1/auth/login",
		middleware.RateLimit(m.RateLimiter, "auth_login", 10, 5, time.Minute),
		m.AuthHandler.Login,
	)

	// ----------------------------
	// Admin Routes (Protected by Session and CIDR)
	// ----------------------------
	admin := router.Group("/admin", middleware.AdminCIDR(cfg.Security.AdminAllowedCIDRs))
	{
		// Admin: Authentication
		admin.POST("/auth/login",
			middleware.RateLimit(m.RateLimiter, "auth_admin_login", 10, 5, time.Minute),
			m.AuthHandler.AdminLogin,
		)
		admin.POST("/auth/logout",
			middleware.RateLimit(m.RateLimiter, "auth_admin_logout", 10, 5, time.Minute),
			m.AuthHandler.AdminLogout,
		)
		admin.GET("/auth/session",
			middleware.RateLimit(m.RateLimiter, "auth_admin_session", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.AuthHandler.AdminSession,
		)

		// Admin: Device management
		admin.GET("/devices/:id",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.DeviceHandler.AdminGetDevice,
		)
		admin.DELETE("/devices/:id",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.DeviceHandler.AdminForceRevoke,
		)
		admin.GET("/devices/:id/quarantine",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.DeviceHandler.Quarantine,
		)
		admin.POST("/devices/:id/suspicious",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.DeviceHandler.AdminMarkSuspicious,
		)
		admin.POST("/devices/cleanup",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.DeviceHandler.AdminCleanupStale,
		)

		// Admin: RBAC
		admin.GET("/rbac/roles",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.RbacHandler.ListRoles,
		)
		admin.POST("/rbac/roles",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.RbacHandler.CreateRole,
		)
		admin.GET("/rbac/roles/:id",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.RbacHandler.GetRole,
		)
		admin.PUT("/rbac/roles/:id",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.RbacHandler.UpdateRole,
		)
		admin.DELETE("/rbac/roles/:id",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.RbacHandler.DeleteRole,
		)
		admin.GET("/rbac/permissions",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.RbacHandler.ListPermissions,
		)
		admin.POST("/rbac/roles/:id/permissions",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.RbacHandler.AssignPermission,
		)
		admin.DELETE("/rbac/roles/:id/permissions/:perm_id",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.RbacHandler.RevokePermission,
		)
		admin.POST("/rbac/cache/invalidate",
			middleware.RateLimit(m.RateLimiter, "admin_devices", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.RbacHandler.InvalidateAll,
		)

		// Admin: OAuth Clients
		admin.POST("/oauth/clients",
			middleware.RateLimit(m.RateLimiter, "oauth_admin", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.OAuthHandler.AdminCreateClient,
		)
		admin.GET("/oauth/clients",
			middleware.RateLimit(m.RateLimiter, "oauth_admin", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.OAuthHandler.AdminListClients,
		)
		admin.GET("/oauth/clients/:client_id",
			middleware.RateLimit(m.RateLimiter, "oauth_admin", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.OAuthHandler.AdminGetClient,
		)
		admin.PUT("/oauth/clients/:client_id",
			middleware.RateLimit(m.RateLimiter, "oauth_admin", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.OAuthHandler.AdminUpdateClient,
		)
		admin.DELETE("/oauth/clients/:client_id",
			middleware.RateLimit(m.RateLimiter, "oauth_admin", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.OAuthHandler.AdminDeleteClient,
		)
		admin.POST("/oauth/clients/:client_id/rotate-secret",
			middleware.RateLimit(m.RateLimiter, "oauth_admin", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.OAuthHandler.AdminRotateClientSecret,
		)
		admin.POST("/oauth/clients/:client_id/grants/revoke",
			middleware.RateLimit(m.RateLimiter, "oauth_admin", 10, 5, time.Minute),
			middleware.AdminSession(m.AdminAuthService.AuthorizeSession),
			m.OAuthHandler.AdminRevokeGrant,
		)
	}

	// quên mật khẩu tài khoản global (không thuộc tenant nào)
	router.POST(
		"/api/v1/auth/forgot-password",
		middleware.RateLimit(m.RateLimiter, "auth_forgot_password", 10, 5, time.Minute),
		m.AuthHandler.ForgotPassword,
	)

	// reset mật khẩu tài khoản global (không thuộc tenant nào)
	router.POST(
		"/api/v1/auth/reset-password",
		middleware.RateLimit(m.RateLimiter, "auth_reset_password", 10, 5, time.Minute),
		m.AuthHandler.ResetPassword,
	)

	// Token rotation — requires device signature.
	router.POST(
		"/api/v1/auth/refresh",
		middleware.RateLimit(m.RateLimiter, "auth_refresh", 10, 5, time.Minute),
		m.TokenHandler.Refresh,
	)

	// Logout — requires valid or near-expired access token to blacklist it.
	router.POST("/api/v1/auth/logout",
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.AuthHandler.Logout,
	)

	router.GET("/api/v1/whoami",
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.AuthHandler.WhoAmI,
	)

	// ----------------------------
	// Device management
	// ----------------------------

	// Self-service: device management (any authenticated user)
	router.GET("/api/v1/me/devices",
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.DeviceHandler.ListMyDevices,
	)

	// delete device self
	router.DELETE("/api/v1/me/devices/:id",
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.DeviceHandler.RevokeDevice,
	)

	// revoke another device , keep device current
	router.DELETE("/api/v1/me/devices/others",
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.DeviceHandler.RevokeOtherDevices,
	)

	// ----------------------------
	// MFA: public challenge flows (no token — in-flight login)
	// ----------------------------
	router.POST("/api/v1/auth/mfa/verify",
		middleware.RateLimit(m.RateLimiter, "mfa_verify", 10, 5, time.Minute),
		m.MfaHandler.Verify,
	)

	// MFA: self-service management (any authenticated user)
	router.GET("/api/v1/me/mfa",
		middleware.RateLimit(m.RateLimiter, "mfa_list", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.MfaHandler.ListMethods,
	)

	// otp enroll
	router.POST("/api/v1/me/mfa/totp/enroll",
		middleware.RateLimit(m.RateLimiter, "mfa_enroll", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.MfaHandler.EnrollTOTP,
	)

	// otp confirm
	router.POST("/api/v1/me/mfa/totp/confirm",
		middleware.RateLimit(m.RateLimiter, "mfa_confirm", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.MfaHandler.ConfirmTOTP,
	)

	// otp enable
	router.PATCH("/api/v1/me/mfa/:setting_id/enable",
		middleware.RateLimit(m.RateLimiter, "mfa_enable", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.MfaHandler.EnableMethod,
	)

	// otp disable
	router.PATCH("/api/v1/me/mfa/:setting_id/disable",
		middleware.RateLimit(m.RateLimiter, "mfa_disable", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.MfaHandler.DisableMethod,
	)

	// otp delete
	router.DELETE("/api/v1/me/mfa/:setting_id",
		middleware.RateLimit(m.RateLimiter, "mfa_delete", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.MfaHandler.DeleteMethod,
	)

	// otp generate recovery codes
	router.POST("/api/v1/me/mfa/recovery-codes",
		middleware.RateLimit(m.RateLimiter, "mfa_recovery_codes", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.MfaHandler.GenerateRecoveryCodes,
	)

	// ----------------------------
	// OAuth2.1 Core
	// ----------------------------
	router.GET("/api/v1/oauth/authorize",
		middleware.RateLimit(m.RateLimiter, "oauth_authorize", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		m.OAuthHandler.Authorize,
	)

	router.POST("/api/v1/oauth/authorize/decision",
		middleware.RateLimit(m.RateLimiter, "oauth_authorize_decision", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		m.OAuthHandler.Decide,
	)

	router.POST("/api/v1/oauth/token",
		middleware.RateLimit(m.RateLimiter, "oauth_token", 10, 5, time.Minute),
		m.OAuthHandler.Token,
	)

	router.POST("/api/v1/oauth/revoke",
		middleware.RateLimit(m.RateLimiter, "oauth_revoke", 10, 5, time.Minute),
		m.OAuthHandler.Revoke,
	)

	router.POST("/api/v1/oauth/introspect",
		middleware.RateLimit(m.RateLimiter, "oauth_introspect", 10, 5, time.Minute),
		m.OAuthHandler.Introspect,
	)

	router.GET("/api/v1/me/oauth/grants",
		middleware.RateLimit(m.RateLimiter, "oauth_me_list_grants", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.OAuthHandler.ListMyGrants,
	)

	router.DELETE("/api/v1/me/oauth/grants/:client_id",
		middleware.RateLimit(m.RateLimiter, "oauth_me_revoke_grant", 10, 5, time.Minute),
		middleware.Access(m.Secrets, m.Rdb),
		middleware.RequireDeviceID(),
		m.OAuthHandler.RevokeMyGrant,
	)

}
