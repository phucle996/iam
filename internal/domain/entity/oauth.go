package entity

import (
	"encoding/json"
	"time"
)

// OAuthClient represents a registered OAuth client.
type OAuthClient struct {
	ID               string
	ClientID         string
	ClientSecretHash string
	Name             string
	RedirectURIs     json.RawMessage
	AllowedScopes    json.RawMessage
	IsActive         bool
	SecretRotatedAt  *time.Time
	Metadata         json.RawMessage
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// OAuthGrant stores a user consent grant for a client.
type OAuthGrant struct {
	ID        string
	UserID    string
	ClientID  string
	Scopes    *json.RawMessage
	CreatedAt time.Time
}

// OAuthAuthorizationCode is a single-use authorization code.
type OAuthAuthorizationCode struct {
	ID                  string
	CodeHash            string
	UserID              string
	ClientID            string
	RedirectURI         string
	Scopes              *json.RawMessage
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	CreatedAt           time.Time
}

// OAuthRefreshToken stores a revocable OAuth refresh token.
type OAuthRefreshToken struct {
	ID            string
	TokenHash     string
	ClientID      string
	UserID        *string
	Scopes        *json.RawMessage
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RotatedFromID *string
	ReplacedByID  *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// OAuthAuthorizeRequest carries parameters for /oauth/authorize precheck.
type OAuthAuthorizeRequest struct {
	UserID              string
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// OAuthAuthorizePreview is returned before user consent decision.
type OAuthAuthorizePreview struct {
	ClientID        string
	ClientName      string
	RedirectURI     string
	RequestedScopes []string
	GrantedScopes   []string
	ConsentRequired bool
	State           string
}

// OAuthAuthorizeDecision contains consent decision input.
type OAuthAuthorizeDecision struct {
	UserID              string
	Approve             bool
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// OAuthAuthorizeDecisionResult carries redirect URI result.
type OAuthAuthorizeDecisionResult struct {
	RedirectURI string
}

// OAuthTokenRequest carries token endpoint input.
type OAuthTokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

// OAuthTokenResponse is token endpoint output.
type OAuthTokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
}

// OAuthRevokeRequest carries revoke endpoint input.
type OAuthRevokeRequest struct {
	Token         string
	TokenTypeHint string
}

// OAuthIntrospectRequest carries introspection input.
type OAuthIntrospectRequest struct {
	Token         string
	TokenTypeHint string
}

// OAuthIntrospection is token introspection response.
type OAuthIntrospection struct {
	Active    bool
	Scope     string
	ClientID  string
	TokenType string
	Sub       string
	Exp       int64
	Iat       int64
}

// OAuthClientCreateRequest contains admin create-client input.
type OAuthClientCreateRequest struct {
	Name          string
	RedirectURIs  []string
	AllowedScopes []string
	IsActive      bool
	Metadata      map[string]any
}

// OAuthClientUpdateRequest contains admin update-client input.
type OAuthClientUpdateRequest struct {
	ClientID      string
	Name          *string
	RedirectURIs  []string
	AllowedScopes []string
	IsActive      *bool
	Metadata      map[string]any
}

// OAuthClientWithSecret returns generated secret once at create/rotate.
type OAuthClientWithSecret struct {
	Client       *OAuthClient
	ClientSecret string
}

// OAuthUserGrant is the self-service representation of a grant.
type OAuthUserGrant struct {
	ClientID   string
	ClientName string
	Scopes     []string
	CreatedAt  time.Time
}
