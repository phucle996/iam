package reqdto

// ForgotPasswordRequest is the payload for initiating a password-reset flow.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest is the payload for completing a password reset.
type ResetPasswordRequest struct {
	NewPassword string `json:"new_password" binding:"required,min=8"`
	RePassword  string `json:"re_password" binding:"required,min=8"`
}
