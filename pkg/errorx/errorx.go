package errorx

import "errors"

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUserInactive           = errors.New("user is inactive")
	ErrTokenGeneration        = errors.New("token generation failed")
	ErrUsernameAlreadyExists  = errors.New("username already exists")
	ErrEmailAlreadyExists     = errors.New("email already exists")
	ErrPhoneAlreadyExists     = errors.New("phone already exists")
	ErrRegistrationFailed     = errors.New("registration failed")
	ErrActivationTokenInvalid = errors.New("activation token invalid")
	ErrActivationTokenExpired = errors.New("activation token expired")
	ErrActivationFailed       = errors.New("activation failed")
	ErrActivationRoleMissing  = errors.New("activation role missing")
	ErrProfileNotFound        = errors.New("profile not found")
	ErrMailJobPublish         = errors.New("mail job publish failed")

	// Device
	ErrDeviceNotFound          = errors.New("device not found")
	ErrDeviceForbidden         = errors.New("device does not belong to user")
	ErrDeviceSuspicious        = errors.New("device is flagged suspicious")
	ErrDeviceChallengeInvalid  = errors.New("device challenge invalid or expired")
	ErrDeviceChallengeNotFound = errors.New("device challenge not found")
	ErrDeviceProofInvalid      = errors.New("device proof signature invalid")
	ErrDeviceKeyRotateFailed   = errors.New("device key rotation failed")
	ErrDeviceBindingRequired   = errors.New("device binding required")
	ErrDeviceKeyInvalid        = errors.New("device key invalid")

	// Password reset
	ErrResetTokenInvalid = errors.New("password reset token invalid")
	ErrResetTokenExpired = errors.New("password reset token expired")
	ErrResetFailed       = errors.New("password reset failed")
	ErrWeakPassword      = errors.New("password does not meet requirements")

	// Refresh token
	ErrRefreshTokenInvalid     = errors.New("refresh token invalid or expired")
	ErrRefreshTokenMismatch    = errors.New("refresh token device mismatch")
	ErrRefreshSignatureInvalid = errors.New("refresh request signature invalid")
	ErrRefreshSignatureExpired = errors.New("refresh request signature timestamp expired")
	ErrRefreshSignatureReplay  = errors.New("refresh request already used")
	ErrRefreshDeviceUnbound    = errors.New("refresh token device is not bound")

	// Admin API key login
	ErrAdminAPIKeyInvalid   = errors.New("admin api key is invalid")
	ErrAdminAPIKeyAuthError = errors.New("admin api key auth unavailable")

	// MFA
	ErrMfaSettingNotFound   = errors.New("mfa setting not found")
	ErrMfaEnrollFailed      = errors.New("mfa enrollment failed")
	ErrMfaChallengeInvalid  = errors.New("mfa challenge invalid or expired")
	ErrMfaChallengeNotFound = errors.New("mfa challenge not found")
	ErrMfaCodeInvalid       = errors.New("mfa code is invalid")
	ErrMfaCodeExpired       = errors.New("mfa code has expired")
	ErrMfaMethodNotAllowed  = errors.New("mfa method not allowed for this challenge")
	ErrMfaRequired          = errors.New("mfa verification required")

	// RBAC
	ErrRoleNotFound       = errors.New("role not found")
	ErrPermissionNotFound = errors.New("permission not found")
	ErrRoleAlreadyExists  = errors.New("role already exists")
)
