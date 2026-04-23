package app

import (
	"controlplane/internal/config"
	"controlplane/internal/ratelimit"
	"controlplane/internal/transport/http/middleware"

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
	rateCfg := config.RateLimitCfg{}
	if cfg != nil {
		rateCfg = cfg.RateLimit
	}

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
		withRateLimit(cfg, m.RateLimiter, "auth_register", rateCfg.Login, m.AuthHandler.Register)...,
	)

	// kích hoạt tài khoản global (không thuộc tenant nào)
	router.GET("/api/v1/auth/activate", m.AuthHandler.Activate)

	// đăng nhập tài khoản global (không thuộc tenant nào)
	router.POST(
		"/api/v1/auth/login",
		withRateLimit(cfg, m.RateLimiter, "auth_login", rateCfg.Login, m.AuthHandler.Login)...,
	)

	// admin login bằng static admin api key, set cookie `apitoken`.
	router.POST(
		"/admin/auth/login",
		withRateLimit(cfg, m.RateLimiter, "auth_admin_api_key_login", rateCfg.Admin, m.AuthHandler.AdminLogin)...,
	)

	// quên mật khẩu tài khoản global (không thuộc tenant nào)
	router.POST(
		"/api/v1/auth/forgot-password",
		withRateLimit(cfg, m.RateLimiter, "auth_forgot_password", rateCfg.Forgot, m.AuthHandler.ForgotPassword)...,
	)

	// reset mật khẩu tài khoản global (không thuộc tenant nào)
	router.POST(
		"/api/v1/auth/reset-password",
		withRateLimit(cfg, m.RateLimiter, "auth_reset_password", rateCfg.Reset, m.AuthHandler.ResetPassword)...,
	)

	// Token rotation — requires device signature.
	router.POST(
		"/api/v1/auth/refresh",
		withRateLimit(cfg, m.RateLimiter, "auth_refresh", rateCfg.Refresh, m.TokenHandler.Refresh)...,
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

	adminAuth := middleware.AdminAPIToken(m.AdminAPITokenService.Authorize)
	adminRate := maybeRateLimit(cfg, m.RateLimiter, "admin_api", rateCfg.Admin)

	// Admin: device management
	router.GET("/admin/devices/:id",
		adminRate,
		adminAuth,
		m.DeviceHandler.AdminGetDevice,
	)

	router.DELETE("/admin/devices/:id",
		adminRate,
		adminAuth,
		m.DeviceHandler.AdminForceRevoke,
	)

	router.GET("/admin/devices/:id/quarantine",
		adminRate,
		adminAuth,
		m.DeviceHandler.Quarantine,
	)
	router.POST("/admin/devices/:id/suspicious",
		adminRate,
		adminAuth,
		m.DeviceHandler.AdminMarkSuspicious,
	)

	router.POST("/admin/devices/cleanup",
		adminRate,
		adminAuth,
		m.DeviceHandler.AdminCleanupStale,
	)

	// ── Admin: RBAC ──────────────

	router.GET("/admin/rbac/roles",
		adminRate,
		adminAuth,
		m.RbacHandler.ListRoles,
	)

	router.POST("/admin/rbac/roles",
		adminRate,
		adminAuth,
		m.RbacHandler.CreateRole,
	)
	router.GET("/admin/rbac/roles/:id",
		adminRate,
		adminAuth,
		m.RbacHandler.GetRole,
	)

	router.PUT("/admin/rbac/roles/:id",
		adminRate,
		adminAuth,
		m.RbacHandler.UpdateRole,
	)

	router.DELETE("/admin/rbac/roles/:id",
		adminRate,
		adminAuth,
		m.RbacHandler.DeleteRole,
	)

	router.GET("/admin/rbac/permissions",
		adminRate,
		adminAuth,
		m.RbacHandler.ListPermissions,
	)

	router.POST("/admin/rbac/roles/:id/permissions",
		adminRate,
		adminAuth,
		m.RbacHandler.AssignPermission,
	)

	router.DELETE("/admin/rbac/roles/:id/permissions/:perm_id",
		adminRate,
		adminAuth,
		m.RbacHandler.RevokePermission,
	)

	router.POST("/admin/rbac/cache/invalidate",
		adminRate,
		adminAuth,
		m.RbacHandler.InvalidateAll,
	)

	// MFA: public challenge flows (no token — in-flight login)
	router.POST("/api/v1/auth/mfa/verify",
		withRateLimit(cfg, m.RateLimiter, "mfa_verify", rateCfg.MFA, m.MfaHandler.Verify)...,
	)

	// MFA: self-service management (any authenticated user)
	router.GET("/api/v1/me/mfa",
		withRateLimit(cfg, m.RateLimiter, "mfa_list", rateCfg.MFA,
			middleware.Access(m.Secrets, m.Rdb),
			middleware.RequireDeviceID(),
			m.MfaHandler.ListMethods,
		)...,
	)

	// otp enroll
	router.POST("/api/v1/me/mfa/totp/enroll",
		withRateLimit(cfg, m.RateLimiter, "mfa_enroll", rateCfg.MFA,
			middleware.Access(m.Secrets, m.Rdb),
			middleware.RequireDeviceID(),
			m.MfaHandler.EnrollTOTP,
		)...,
	)

	// otp confirm
	router.POST("/api/v1/me/mfa/totp/confirm",
		withRateLimit(cfg, m.RateLimiter, "mfa_confirm", rateCfg.MFA,
			middleware.Access(m.Secrets, m.Rdb),
			middleware.RequireDeviceID(),
			m.MfaHandler.ConfirmTOTP,
		)...,
	)

	// otp enable
	router.PATCH("/api/v1/me/mfa/:setting_id/enable",
		withRateLimit(cfg, m.RateLimiter, "mfa_enable", rateCfg.MFA,
			middleware.Access(m.Secrets, m.Rdb),
			middleware.RequireDeviceID(),
			m.MfaHandler.EnableMethod,
		)...,
	)

	// otp disable
	router.PATCH("/api/v1/me/mfa/:setting_id/disable",
		withRateLimit(cfg, m.RateLimiter, "mfa_disable", rateCfg.MFA,
			middleware.Access(m.Secrets, m.Rdb),
			middleware.RequireDeviceID(),
			m.MfaHandler.DisableMethod,
		)...,
	)

	// otp delete
	router.DELETE("/api/v1/me/mfa/:setting_id",
		withRateLimit(cfg, m.RateLimiter, "mfa_delete", rateCfg.MFA,
			middleware.Access(m.Secrets, m.Rdb),
			middleware.RequireDeviceID(),
			m.MfaHandler.DeleteMethod,
		)...,
	)

	// otp generate recovery codes
	router.POST("/api/v1/me/mfa/recovery-codes",
		withRateLimit(cfg, m.RateLimiter, "mfa_recovery_codes", rateCfg.MFA,
			middleware.Access(m.Secrets, m.Rdb),
			middleware.RequireDeviceID(),
			m.MfaHandler.GenerateRecoveryCodes,
		)...,
	)

}

func withRateLimit(
	cfg *config.Config,
	limiter *ratelimit.Bucket,
	name string,
	rate config.RateLimitEndpointCfg,
	handlers ...gin.HandlerFunc,
) []gin.HandlerFunc {
	if cfg == nil || !cfg.App.EnableRateLimit {
		return handlers
	}

	out := make([]gin.HandlerFunc, 0, len(handlers)+1)
	out = append(out, middleware.RateLimit(limiter, name, rate.Capacity, rate.Refill, rate.Period))
	out = append(out, handlers...)
	return out
}

func maybeRateLimit(cfg *config.Config, limiter *ratelimit.Bucket, name string, rate config.RateLimitEndpointCfg) gin.HandlerFunc {
	if cfg == nil || !cfg.App.EnableRateLimit {
		return func(c *gin.Context) { c.Next() }
	}
	return middleware.RateLimit(limiter, name, rate.Capacity, rate.Refill, rate.Period)
}
