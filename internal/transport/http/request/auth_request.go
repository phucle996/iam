package reqdto

type LoginRequest struct {
	Username           string `json:"username" binding:"required"`
	Password           string `json:"password" binding:"required"`
	DeviceFingerprint  string `json:"device_fingerprint" binding:"required"`
	DevicePublicKey    string `json:"device_public_key" binding:"required"`
	DeviceKeyAlgorithm string `json:"device_key_algorithm,omitempty"`
}

type RegisterRequest struct {
	FullName    string  `json:"full_name" binding:"required,min=2,max=120"`
	Email       string  `json:"email" binding:"required,email"`
	Username    string  `json:"username" binding:"required,min=3,max=32"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	Password    string  `json:"password" binding:"required,min=8"`
	RePassword  string  `json:"re_password" binding:"required,min=8"`
}

type AdminAPIKeyLoginRequest struct {
	APIKey string `json:"api_key" binding:"required"`
}
