package iam_resdto

type WhoamiResponse struct {
	UserID         string   `json:"user_id"`
	Username       string   `json:"username"`
	Email          string   `json:"email"`
	Phone          string   `json:"phone"`
	FullName       string   `json:"full_name"`
	Company        string   `json:"company"`
	ReferralSource string   `json:"referral_source"`
	JobFunction    string   `json:"job_function"`
	Country        string   `json:"country"`
	AvatarURL      string   `json:"avatar_url"`
	Bio            string   `json:"bio"`
	Status         string   `json:"status"`
	OnBoarding     bool     `json:"on_boarding"`
	Level          int16    `json:"level,omitempty"`
	AuthType       string   `json:"auth_type"`
	SessionID      string   `json:"session_id,omitempty"`
	Roles          []string `json:"roles"`
	Permissions    []string `json:"permissions"`
}
