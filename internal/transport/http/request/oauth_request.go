package reqdto

// OAuthAuthorizeQuery captures /api/v1/oauth/authorize query parameters.
type OAuthAuthorizeQuery struct {
	ResponseType        string `form:"response_type" binding:"required"`
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	CodeChallenge       string `form:"code_challenge" binding:"required"`
	CodeChallengeMethod string `form:"code_challenge_method" binding:"required"`
}

// OAuthAuthorizeDecisionRequest captures consent decision payload.
type OAuthAuthorizeDecisionRequest struct {
	Approve             bool   `json:"approve"`
	ResponseType        string `json:"response_type" binding:"required"`
	ClientID            string `json:"client_id" binding:"required"`
	RedirectURI         string `json:"redirect_uri" binding:"required"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge" binding:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" binding:"required"`
}

// OAuthTokenRequest captures token endpoint payload.
type OAuthTokenRequest struct {
	GrantType    string `form:"grant_type" json:"grant_type" binding:"required"`
	Code         string `form:"code" json:"code"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`
	CodeVerifier string `form:"code_verifier" json:"code_verifier"`
	RefreshToken string `form:"refresh_token" json:"refresh_token"`
	Scope        string `form:"scope" json:"scope"`
	ClientID     string `form:"client_id" json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
}

// OAuthRevokeRequest captures revoke endpoint payload.
type OAuthRevokeRequest struct {
	Token         string `form:"token" json:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint"`
	ClientID      string `form:"client_id" json:"client_id"`
	ClientSecret  string `form:"client_secret" json:"client_secret"`
}

// OAuthIntrospectRequest captures introspection payload.
type OAuthIntrospectRequest struct {
	Token         string `form:"token" json:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint"`
	ClientID      string `form:"client_id" json:"client_id"`
	ClientSecret  string `form:"client_secret" json:"client_secret"`
}

// OAuthClientCreateRequest captures admin create-client payload.
type OAuthClientCreateRequest struct {
	Name          string         `json:"name" binding:"required"`
	RedirectURIs  []string       `json:"redirect_uris" binding:"required"`
	AllowedScopes []string       `json:"allowed_scopes"`
	IsActive      *bool          `json:"is_active"`
	Metadata      map[string]any `json:"metadata"`
}

// OAuthClientUpdateRequest captures admin update-client payload.
type OAuthClientUpdateRequest struct {
	Name          *string        `json:"name"`
	RedirectURIs  []string       `json:"redirect_uris"`
	AllowedScopes []string       `json:"allowed_scopes"`
	IsActive      *bool          `json:"is_active"`
	Metadata      map[string]any `json:"metadata"`
}

// OAuthListClientsQuery captures client list paging.
type OAuthListClientsQuery struct {
	Limit  int `form:"limit"`
	Offset int `form:"offset"`
}

// OAuthAdminRevokeGrantRequest captures admin grant revoke payload.
type OAuthAdminRevokeGrantRequest struct {
	UserID string `json:"user_id" binding:"required"`
}
