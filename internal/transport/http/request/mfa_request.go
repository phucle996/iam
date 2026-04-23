package reqdto

// ── MFA Challenge ─────────────────────────────────────────────────────────────

// MfaVerifyRequest is the payload to complete an in-progress MFA challenge.
type MfaVerifyRequest struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
	Method      string `json:"method" binding:"required"` // totp | sms | email | recovery
	Code        string `json:"code" binding:"required"`
}

// MfaSendOTPRequest asks the server to (re)send an OTP via the given method.
type MfaSendOTPRequest struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
	Method      string `json:"method" binding:"required"` // sms | email
}

// ── Enrollment ────────────────────────────────────────────────────────────────

// MfaEnrollTOTPRequest starts a TOTP enrollment.
type MfaEnrollTOTPRequest struct {
	DeviceName string `json:"device_name" binding:"required"`
}

// MfaConfirmTOTPRequest finishes TOTP enrollment by supplying the first valid code.
type MfaConfirmTOTPRequest struct {
	SettingID string `json:"setting_id" binding:"required"`
	Code      string `json:"code" binding:"required,len=6"`
}

// MfaEnrollSMSRequest enrolls an SMS-based MFA method.
type MfaEnrollSMSRequest struct {
	DeviceName string `json:"device_name" binding:"required"`
}

// MfaEnrollEmailRequest enrolls an email-based MFA method.
type MfaEnrollEmailRequest struct {
	DeviceName string `json:"device_name" binding:"required"`
}

// ── Management ────────────────────────────────────────────────────────────────

// MfaSetPrimaryRequest designates a method as primary.
type MfaSetPrimaryRequest struct {
	SettingID string `json:"setting_id" binding:"required"`
}
