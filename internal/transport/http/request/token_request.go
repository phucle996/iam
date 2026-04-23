package reqdto

// RefreshTokenRequest is the client payload for obtaining a new token pair.
//
// The client MUST sign the canonical payload:
//
//	jti + "\n" + iat + "\n" + htm + "\n" + htu + "\n" + token_hash + "\n" + device_id
//
// with its device private key and base64-raw-url encode the resulting bytes
// as the `signature` field.
type RefreshTokenRequest struct {
	// JTI is the proof identifier for replay detection.
	JTI string `json:"jti" binding:"required"`

	// IssuedAt is the Unix epoch seconds at which the proof was signed.
	IssuedAt int64 `json:"iat" binding:"required"`

	// HTM is the HTTP method that was signed.
	HTM string `json:"htm" binding:"required"`

	// HTU is the absolute refresh endpoint URL that was signed.
	HTU string `json:"htu" binding:"required"`

	// TokenHash is the readable refresh-token hash companion cookie value.
	TokenHash string `json:"token_hash" binding:"required"`

	// DeviceID is the readable device-id companion cookie value.
	DeviceID string `json:"device_id" binding:"required"`

	// Signature is required for refresh rotation.
	Signature string `json:"signature" binding:"required"`
}
