package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"iam/internal/config"
	"iam/internal/domain/entity"
	domainrepo "iam/internal/domain/repository"
	"iam/internal/security"
	"iam/pkg/errorx"
	"iam/pkg/id"

	"github.com/redis/go-redis/v9"
)

const (
	oauthClientPrefix          = "cli_"
	oauthTokenTypeBearer       = "Bearer"
	oauthAccessTokenUse        = "access"
	oauthClientTokenUse        = "client"
	oauthAccessBlacklistKey    = "iam:oauth:access:revoked:"
	oauthDefaultClientPageSize = 50
)

// OAuthService implements domainsvc.OAuthService.
type OAuthService struct {
	repo    domainrepo.OAuthRepository
	secrets security.SecretProvider
	cfg     *config.Config
	rdb     *redis.Client
}

func NewOAuthService(
	repo domainrepo.OAuthRepository,
	secrets security.SecretProvider,
	cfg *config.Config,
	rdb *redis.Client,
) *OAuthService {
	return &OAuthService{
		repo:    repo,
		secrets: secrets,
		cfg:     cfg,
		rdb:     rdb,
	}
}

func (s *OAuthService) Authorize(ctx context.Context, req *entity.OAuthAuthorizeRequest) (*entity.OAuthAuthorizePreview, error) {

	request, err := s.normalizeAuthorizeRequest(req)
	if err != nil {
		return nil, err
	}

	client, err := s.repo.GetClientByClientID(ctx, request.ClientID)
	if err != nil {
		if errors.Is(err, errorx.ErrOAuthClientNotFound) {
			return nil, errorx.ErrOAuthInvalidClient
		}
		return nil, err
	}
	if !client.IsActive {
		return nil, errorx.ErrOAuthClientInactive
	}

	if !containsString(parseRawJSONStrings(client.RedirectURIs), request.RedirectURI) {
		return nil, errorx.ErrOAuthInvalidRedirectURI
	}

	requestedScopes, err := s.normalizeRequestedScopes(request.Scope, client)
	if err != nil {
		return nil, err
	}

	grantedScopes := make([]string, 0)
	consentRequired := true
	grant, err := s.repo.GetGrant(ctx, request.UserID, client.ID)
	if err == nil && grant != nil {
		grantedScopes = parseRawJSONStringsPtr(grant.Scopes)
		if isSubset(requestedScopes, grantedScopes) {
			consentRequired = false
		}
	} else if err != nil && !errors.Is(err, errorx.ErrOAuthGrantNotFound) {
		return nil, err
	}

	return &entity.OAuthAuthorizePreview{
		ClientID:        client.ClientID,
		ClientName:      client.Name,
		RedirectURI:     request.RedirectURI,
		RequestedScopes: requestedScopes,
		GrantedScopes:   grantedScopes,
		ConsentRequired: consentRequired,
		State:           request.State,
	}, nil
}

func (s *OAuthService) Decide(ctx context.Context, req *entity.OAuthAuthorizeDecision) (*entity.OAuthAuthorizeDecisionResult, error) {
	if s == nil || s.repo == nil || req == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	normalizedReq, err := s.normalizeAuthorizeRequest(&entity.OAuthAuthorizeRequest{
		UserID:              req.UserID,
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})
	if err != nil {
		return nil, err
	}

	client, err := s.repo.GetClientByClientID(ctx, normalizedReq.ClientID)
	if err != nil {
		if errors.Is(err, errorx.ErrOAuthClientNotFound) {
			return nil, errorx.ErrOAuthInvalidClient
		}
		return nil, err
	}
	if !client.IsActive {
		return nil, errorx.ErrOAuthClientInactive
	}

	if !containsString(parseRawJSONStrings(client.RedirectURIs), normalizedReq.RedirectURI) {
		return nil, errorx.ErrOAuthInvalidRedirectURI
	}

	if !req.Approve {
		return &entity.OAuthAuthorizeDecisionResult{
			RedirectURI: buildOAuthRedirectURI(normalizedReq.RedirectURI, map[string]string{
				"error":             "access_denied",
				"error_description": "the resource owner denied the request",
				"state":             normalizedReq.State,
			}),
		}, nil
	}

	requestedScopes, err := s.normalizeRequestedScopes(normalizedReq.Scope, client)
	if err != nil {
		return nil, err
	}

	scopesJSON, err := json.Marshal(requestedScopes)
	if err != nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	grantID, err := id.Generate()
	if err != nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}
	grant := &entity.OAuthGrant{
		ID:       grantID,
		UserID:   normalizedReq.UserID,
		ClientID: client.ID,
		Scopes:   rawJSONPtr(scopesJSON),
	}
	if err := s.repo.UpsertGrant(ctx, grant); err != nil {
		return nil, err
	}

	activeAccessSecret, err := s.secrets.GetActive(security.SecretFamilyOAuthAccess)
	if err != nil {
		return nil, errorx.ErrTokenGeneration
	}

	rawCode, err := security.GenerateToken(56, activeAccessSecret.Value)
	if err != nil {
		return nil, errorx.ErrTokenGeneration
	}
	codeHash, err := security.HashToken(rawCode, activeAccessSecret.Value)
	if err != nil {
		return nil, errorx.ErrTokenGeneration
	}
	codeID, err := id.Generate()
	if err != nil {
		return nil, errorx.ErrTokenGeneration
	}

	now := time.Now().UTC()
	authCode := &entity.OAuthAuthorizationCode{
		ID:                  codeID,
		CodeHash:            codeHash,
		UserID:              normalizedReq.UserID,
		ClientID:            client.ID,
		RedirectURI:         normalizedReq.RedirectURI,
		Scopes:              rawJSONPtr(scopesJSON),
		CodeChallenge:       normalizedReq.CodeChallenge,
		CodeChallengeMethod: normalizedReq.CodeChallengeMethod,
		ExpiresAt:           now.Add(s.oauthAuthCodeTTL()),
	}

	if err := s.repo.CreateAuthorizationCode(ctx, authCode); err != nil {
		return nil, err
	}

	return &entity.OAuthAuthorizeDecisionResult{
		RedirectURI: buildOAuthRedirectURI(normalizedReq.RedirectURI, map[string]string{
			"code":  rawCode,
			"state": normalizedReq.State,
		}),
	}, nil
}

func (s *OAuthService) Token(ctx context.Context, req *entity.OAuthTokenRequest, clientID, clientSecret string) (*entity.OAuthTokenResponse, error) {
	if s == nil || s.repo == nil || req == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	switch strings.TrimSpace(req.GrantType) {
	case "authorization_code":
		return s.issueByAuthorizationCode(ctx, client, req)
	case "refresh_token":
		return s.issueByRefreshToken(ctx, client, req)
	case "client_credentials":
		return s.issueClientCredentials(ctx, client, req)
	default:
		return nil, errorx.ErrOAuthUnsupportedGrantType
	}
}

func (s *OAuthService) Revoke(ctx context.Context, req *entity.OAuthRevokeRequest, clientID, clientSecret string) error {
	if s == nil || req == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil
	}

	if strings.Count(token, ".") == 2 {
		claims, err := s.parseOAuthAccessToken(token)
		if err == nil && strings.EqualFold(strings.TrimSpace(claims.ClientID), strings.TrimSpace(client.ClientID)) {
			s.blacklistAccessToken(ctx, claims)
		}
		return nil
	}

	for _, hash := range s.hashWithCandidates(token, security.SecretFamilyOAuthRefresh) {
		_, _ = s.repo.RevokeRefreshTokenByHash(ctx, hash, time.Now().UTC())
	}

	return nil
}

func (s *OAuthService) Introspect(ctx context.Context, req *entity.OAuthIntrospectRequest, clientID, clientSecret string) (*entity.OAuthIntrospection, error) {
	if s == nil || req == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		return &entity.OAuthIntrospection{Active: false}, nil
	}

	if strings.Count(token, ".") == 2 {
		claims, err := s.parseOAuthAccessToken(token)
		if err != nil {
			return &entity.OAuthIntrospection{Active: false}, nil
		}
		if !strings.EqualFold(strings.TrimSpace(claims.ClientID), strings.TrimSpace(client.ClientID)) {
			return &entity.OAuthIntrospection{Active: false}, nil
		}
		if s.isAccessTokenRevoked(ctx, claims.TokenID) {
			return &entity.OAuthIntrospection{Active: false}, nil
		}
		return &entity.OAuthIntrospection{
			Active:    true,
			Scope:     claims.Scope,
			ClientID:  claims.ClientID,
			TokenType: "access_token",
			Sub:       claims.Subject,
			Exp:       claims.ExpiresAt,
			Iat:       claims.IssuedAt,
		}, nil
	}

	for _, hash := range s.hashWithCandidates(token, security.SecretFamilyOAuthRefresh) {
		rt, err := s.repo.GetRefreshTokenByHash(ctx, hash)
		if err != nil {
			if errors.Is(err, errorx.ErrOAuthInvalidGrant) {
				continue
			}
			return nil, err
		}
		if rt == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rt.ClientID), strings.TrimSpace(client.ID)) {
			return &entity.OAuthIntrospection{Active: false}, nil
		}
		return &entity.OAuthIntrospection{
			Active:    true,
			Scope:     strings.Join(parseRawJSONStringsPtr(rt.Scopes), " "),
			ClientID:  client.ClientID,
			TokenType: "refresh_token",
			Sub:       derefString(rt.UserID),
			Exp:       rt.ExpiresAt.Unix(),
			Iat:       rt.CreatedAt.Unix(),
		}, nil
	}

	return &entity.OAuthIntrospection{Active: false}, nil
}

func (s *OAuthService) CreateClient(ctx context.Context, req *entity.OAuthClientCreateRequest) (*entity.OAuthClientWithSecret, error) {
	if s == nil || s.repo == nil || req == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 120 {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	redirectURIs, err := normalizeRedirectURIs(req.RedirectURIs)
	if err != nil {
		return nil, errorx.ErrOAuthInvalidRedirectURI
	}

	allowedScopes, err := s.normalizeAllowedScopes(req.AllowedScopes)
	if err != nil {
		return nil, err
	}

	metaJSON, err := json.Marshal(req.Metadata)
	if err != nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}
	if len(metaJSON) == 0 || string(metaJSON) == "null" {
		metaJSON = []byte("{}")
	}

	idValue, err := id.Generate()
	if err != nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}
	clientID := oauthClientPrefix + strings.ToLower(idValue)

	now := time.Now().UTC()
	secret, err := s.generateClientSecret()
	if err != nil {
		return nil, err
	}

	client := &entity.OAuthClient{
		ID:               idValue,
		ClientID:         clientID,
		ClientSecretHash: hashClientSecret(secret),
		Name:             name,
		RedirectURIs:     mustMarshalJSON(redirectURIs, []byte("[]")),
		AllowedScopes:    mustMarshalJSON(allowedScopes, []byte("[]")),
		IsActive:         req.IsActive,
		SecretRotatedAt:  &now,
		Metadata:         metaJSON,
	}
	if !req.IsActive {
		client.IsActive = false
	}

	if err := s.repo.CreateClient(ctx, client); err != nil {
		return nil, err
	}

	stored, err := s.repo.GetClientByClientID(ctx, client.ClientID)
	if err != nil {
		return nil, err
	}
	if stored != nil {
		stored.ClientSecretHash = ""
	}

	return &entity.OAuthClientWithSecret{
		Client:       stored,
		ClientSecret: secret,
	}, nil
}

func (s *OAuthService) ListClients(ctx context.Context, limit, offset int) ([]*entity.OAuthClient, error) {
	if s == nil || s.repo == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}
	if limit <= 0 {
		limit = oauthDefaultClientPageSize
	}

	clients, err := s.repo.ListClients(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	for _, c := range clients {
		if c != nil {
			c.ClientSecretHash = ""
		}
	}
	return clients, nil
}

func (s *OAuthService) GetClient(ctx context.Context, clientID string) (*entity.OAuthClient, error) {
	if s == nil || s.repo == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	client, err := s.repo.GetClientByClientID(ctx, strings.TrimSpace(clientID))
	if err != nil {
		return nil, err
	}
	if client != nil {
		client.ClientSecretHash = ""
	}
	return client, nil
}

func (s *OAuthService) UpdateClient(ctx context.Context, req *entity.OAuthClientUpdateRequest) (*entity.OAuthClient, error) {
	if s == nil || s.repo == nil || req == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	current, err := s.repo.GetClientByClientID(ctx, strings.TrimSpace(req.ClientID))
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, errorx.ErrOAuthClientNotFound
	}

	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" || len(name) > 120 {
			return nil, errorx.ErrOAuthInvalidRequest
		}
		current.Name = name
	}
	if req.RedirectURIs != nil {
		redirectURIs, err := normalizeRedirectURIs(req.RedirectURIs)
		if err != nil {
			return nil, errorx.ErrOAuthInvalidRedirectURI
		}
		current.RedirectURIs = mustMarshalJSON(redirectURIs, []byte("[]"))
	}
	if req.AllowedScopes != nil {
		allowedScopes, err := s.normalizeAllowedScopes(req.AllowedScopes)
		if err != nil {
			return nil, err
		}
		current.AllowedScopes = mustMarshalJSON(allowedScopes, []byte("[]"))
	}
	if req.IsActive != nil {
		current.IsActive = *req.IsActive
	}
	if req.Metadata != nil {
		metaJSON, err := json.Marshal(req.Metadata)
		if err != nil {
			return nil, errorx.ErrOAuthInvalidRequest
		}
		current.Metadata = metaJSON
	}

	if err := s.repo.UpdateClient(ctx, current); err != nil {
		return nil, err
	}

	updated, err := s.repo.GetClientByClientID(ctx, current.ClientID)
	if err != nil {
		return nil, err
	}
	if updated != nil {
		updated.ClientSecretHash = ""
	}
	return updated, nil
}

func (s *OAuthService) DeleteClient(ctx context.Context, clientID string) error {
	if s == nil || s.repo == nil {
		return errorx.ErrOAuthInvalidRequest
	}
	return s.repo.DeleteClientByClientID(ctx, strings.TrimSpace(clientID))
}

func (s *OAuthService) RotateClientSecret(ctx context.Context, clientID string) (*entity.OAuthClientWithSecret, error) {
	if s == nil || s.repo == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	clientID = strings.TrimSpace(clientID)
	client, err := s.repo.GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errorx.ErrOAuthClientNotFound
	}

	secret, err := s.generateClientSecret()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if err := s.repo.RotateClientSecret(ctx, clientID, hashClientSecret(secret), now); err != nil {
		return nil, err
	}

	updated, err := s.repo.GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if updated != nil {
		updated.ClientSecretHash = ""
	}

	return &entity.OAuthClientWithSecret{
		Client:       updated,
		ClientSecret: secret,
	}, nil
}

func (s *OAuthService) ListMyGrants(ctx context.Context, userID string) ([]*entity.OAuthUserGrant, error) {
	if s == nil || s.repo == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	grants, err := s.repo.ListGrantsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]*entity.OAuthUserGrant, 0, len(grants))
	for _, grant := range grants {
		if grant == nil {
			continue
		}
		client, err := s.repo.GetClientByID(ctx, grant.ClientID)
		if err != nil {
			if errors.Is(err, errorx.ErrOAuthClientNotFound) {
				continue
			}
			return nil, err
		}
		result = append(result, &entity.OAuthUserGrant{
			ClientID:   client.ClientID,
			ClientName: client.Name,
			Scopes:     parseRawJSONStringsPtr(grant.Scopes),
			CreatedAt:  grant.CreatedAt,
		})
	}

	return result, nil
}

func (s *OAuthService) RevokeMyGrant(ctx context.Context, userID, clientID string) error {
	if s == nil || s.repo == nil {
		return errorx.ErrOAuthInvalidRequest
	}

	client, err := s.repo.GetClientByClientID(ctx, strings.TrimSpace(clientID))
	if err != nil {
		return err
	}
	return s.repo.RevokeGrant(ctx, strings.TrimSpace(userID), client.ID)
}

func (s *OAuthService) AdminRevokeGrant(ctx context.Context, userID, clientID string) error {
	return s.RevokeMyGrant(ctx, userID, clientID)
}

func (s *OAuthService) issueByAuthorizationCode(ctx context.Context, client *entity.OAuthClient, req *entity.OAuthTokenRequest) (*entity.OAuthTokenResponse, error) {
	rawCode := strings.TrimSpace(req.Code)
	redirectURI := strings.TrimSpace(req.RedirectURI)
	codeVerifier := strings.TrimSpace(req.CodeVerifier)

	if rawCode == "" || redirectURI == "" || codeVerifier == "" {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	consumedAt := time.Now().UTC()
	var consumed *entity.OAuthAuthorizationCode
	for _, hash := range s.hashWithCandidates(rawCode, security.SecretFamilyOAuthAccess) {
		code, err := s.repo.ConsumeAuthorizationCode(ctx, hash, consumedAt)
		if err != nil {
			if errors.Is(err, errorx.ErrOAuthCodeNotFound) ||
				errors.Is(err, errorx.ErrOAuthCodeExpired) ||
				errors.Is(err, errorx.ErrOAuthCodeConsumed) ||
				errors.Is(err, errorx.ErrOAuthInvalidGrant) {
				continue
			}
			return nil, err
		}
		if code != nil {
			consumed = code
			break
		}
	}
	if consumed == nil {
		return nil, errorx.ErrOAuthInvalidGrant
	}

	if !strings.EqualFold(strings.TrimSpace(consumed.ClientID), strings.TrimSpace(client.ID)) {
		return nil, errorx.ErrOAuthInvalidGrant
	}
	if !strings.EqualFold(strings.TrimSpace(consumed.RedirectURI), redirectURI) {
		return nil, errorx.ErrOAuthInvalidGrant
	}

	expectedChallenge := pkceS256(codeVerifier)
	if consumed.CodeChallengeMethod != "S256" {
		return nil, errorx.ErrOAuthInvalidPKCE
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(consumed.CodeChallenge)), []byte(expectedChallenge)) != 1 {
		return nil, errorx.ErrOAuthInvalidPKCE
	}

	scopes := parseRawJSONStringsPtr(consumed.Scopes)
	accessToken, expiresAt, tokenID, err := s.signOAuthAccessToken(client, ptrString(consumed.UserID), scopes, oauthAccessTokenUse)
	if err != nil {
		return nil, err
	}
	_ = tokenID

	refreshRaw, refreshHash, err := s.generateOAuthRefreshToken()
	if err != nil {
		return nil, err
	}
	refreshID, err := id.Generate()
	if err != nil {
		return nil, errorx.ErrTokenGeneration
	}
	refreshExpiry := time.Now().UTC().Add(s.oauthRefreshTTL())
	userID := strings.TrimSpace(consumed.UserID)
	refreshEntity := &entity.OAuthRefreshToken{
		ID:        refreshID,
		TokenHash: refreshHash,
		ClientID:  client.ID,
		UserID:    &userID,
		Scopes:    mustMarshalJSONPtr(scopes),
		ExpiresAt: refreshExpiry,
	}
	if err := s.repo.CreateRefreshToken(ctx, refreshEntity); err != nil {
		return nil, err
	}

	return &entity.OAuthTokenResponse{
		AccessToken:  accessToken,
		TokenType:    oauthTokenTypeBearer,
		ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
		RefreshToken: refreshRaw,
		Scope:        strings.Join(scopes, " "),
	}, nil
}

func (s *OAuthService) issueByRefreshToken(ctx context.Context, client *entity.OAuthClient, req *entity.OAuthTokenRequest) (*entity.OAuthTokenResponse, error) {
	rawRefresh := strings.TrimSpace(req.RefreshToken)
	if rawRefresh == "" {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	tokenHash, current, err := s.lookupOAuthRefreshToken(ctx, rawRefresh)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, errorx.ErrOAuthInvalidGrant
	}
	if !strings.EqualFold(strings.TrimSpace(current.ClientID), strings.TrimSpace(client.ID)) {
		return nil, errorx.ErrOAuthInvalidGrant
	}

	scopes := parseRawJSONStringsPtr(current.Scopes)
	if scope := strings.TrimSpace(req.Scope); scope != "" {
		overrideScopes, err := s.normalizeRequestedScopes(scope, client)
		if err != nil {
			return nil, err
		}
		if !isSubset(overrideScopes, scopes) {
			return nil, errorx.ErrOAuthInvalidScope
		}
		scopes = overrideScopes
	}

	newRaw, newHash, err := s.generateOAuthRefreshToken()
	if err != nil {
		return nil, err
	}
	newID, err := id.Generate()
	if err != nil {
		return nil, errorx.ErrTokenGeneration
	}

	now := time.Now().UTC()
	consumed, err := s.repo.ConsumeRefreshToken(ctx, tokenHash, newID, now)
	if err != nil {
		if errors.Is(err, errorx.ErrOAuthReplayDetected) {
			return nil, errorx.ErrOAuthReplayDetected
		}
		if errors.Is(err, errorx.ErrOAuthTokenExpired) {
			return nil, errorx.ErrOAuthTokenExpired
		}
		if errors.Is(err, errorx.ErrOAuthInvalidGrant) {
			return nil, errorx.ErrOAuthInvalidGrant
		}
		return nil, err
	}
	if consumed == nil {
		return nil, errorx.ErrOAuthInvalidGrant
	}

	newRT := &entity.OAuthRefreshToken{
		ID:            newID,
		TokenHash:     newHash,
		ClientID:      consumed.ClientID,
		UserID:        consumed.UserID,
		Scopes:        mustMarshalJSONPtr(scopes),
		ExpiresAt:     now.Add(s.oauthRefreshTTL()),
		RotatedFromID: ptrString(consumed.ID),
	}
	if err := s.repo.CreateRefreshToken(ctx, newRT); err != nil {
		return nil, err
	}

	accessToken, expiresAt, _, err := s.signOAuthAccessToken(client, consumed.UserID, scopes, oauthAccessTokenUse)
	if err != nil {
		return nil, err
	}

	return &entity.OAuthTokenResponse{
		AccessToken:  accessToken,
		TokenType:    oauthTokenTypeBearer,
		ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
		RefreshToken: newRaw,
		Scope:        strings.Join(scopes, " "),
	}, nil
}

func (s *OAuthService) issueClientCredentials(_ context.Context, client *entity.OAuthClient, req *entity.OAuthTokenRequest) (*entity.OAuthTokenResponse, error) {
	scopes, err := s.normalizeRequestedScopes(req.Scope, client)
	if err != nil {
		return nil, err
	}

	subject := strings.TrimSpace(client.ClientID)
	accessToken, expiresAt, _, err := s.signOAuthAccessToken(client, &subject, scopes, oauthClientTokenUse)
	if err != nil {
		return nil, err
	}

	return &entity.OAuthTokenResponse{
		AccessToken: accessToken,
		TokenType:   oauthTokenTypeBearer,
		ExpiresIn:   int64(time.Until(expiresAt).Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

func (s *OAuthService) authenticateClient(ctx context.Context, clientID, clientSecret string) (*entity.OAuthClient, error) {
	if s == nil || s.repo == nil {
		return nil, errorx.ErrOAuthInvalidClient
	}

	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)
	if clientID == "" || clientSecret == "" {
		return nil, errorx.ErrOAuthInvalidClient
	}

	client, err := s.repo.GetClientByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, errorx.ErrOAuthClientNotFound) {
			return nil, errorx.ErrOAuthInvalidClient
		}
		return nil, err
	}
	if client == nil || !client.IsActive {
		return nil, errorx.ErrOAuthInvalidClient
	}

	expected := hashClientSecret(clientSecret)
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(client.ClientSecretHash)), []byte(expected)) != 1 {
		return nil, errorx.ErrOAuthInvalidClient
	}

	return client, nil
}

func (s *OAuthService) normalizeAuthorizeRequest(req *entity.OAuthAuthorizeRequest) (*entity.OAuthAuthorizeRequest, error) {
	if req == nil {
		return nil, errorx.ErrOAuthInvalidRequest
	}

	normalized := &entity.OAuthAuthorizeRequest{
		UserID:              strings.TrimSpace(req.UserID),
		ResponseType:        strings.TrimSpace(req.ResponseType),
		ClientID:            strings.TrimSpace(req.ClientID),
		RedirectURI:         strings.TrimSpace(req.RedirectURI),
		Scope:               strings.TrimSpace(req.Scope),
		State:               strings.TrimSpace(req.State),
		CodeChallenge:       strings.TrimSpace(req.CodeChallenge),
		CodeChallengeMethod: strings.ToUpper(strings.TrimSpace(req.CodeChallengeMethod)),
	}
	if normalized.UserID == "" || normalized.ClientID == "" || normalized.RedirectURI == "" {
		return nil, errorx.ErrOAuthInvalidRequest
	}
	if normalized.ResponseType != "code" {
		return nil, errorx.ErrOAuthUnsupportedRespType
	}
	if normalized.CodeChallenge == "" {
		return nil, errorx.ErrOAuthInvalidPKCE
	}
	if normalized.CodeChallengeMethod == "" {
		normalized.CodeChallengeMethod = "S256"
	}
	if normalized.CodeChallengeMethod != "S256" {
		return nil, errorx.ErrOAuthInvalidPKCE
	}

	return normalized, nil
}

func (s *OAuthService) normalizeAllowedScopes(scopes []string) ([]string, error) {
	globalAllowed := makeStringSet(normalizeScopeSlice(s.cfg.App.OAuthAllowedScopes))
	if len(globalAllowed) == 0 {
		return nil, errorx.ErrOAuthInvalidScope
	}

	normalized := normalizeScopeSlice(scopes)
	if len(normalized) == 0 {
		result := make([]string, 0, len(globalAllowed))
		for scope := range globalAllowed {
			result = append(result, scope)
		}
		sort.Strings(result)
		return result, nil
	}

	for _, scope := range normalized {
		if _, ok := globalAllowed[scope]; !ok {
			return nil, errorx.ErrOAuthInvalidScope
		}
	}
	return normalized, nil
}

func (s *OAuthService) normalizeRequestedScopes(scopeRaw string, client *entity.OAuthClient) ([]string, error) {
	requested := normalizeScopeSlice(strings.Fields(strings.TrimSpace(scopeRaw)))
	globalAllowed := makeStringSet(normalizeScopeSlice(s.cfg.App.OAuthAllowedScopes))
	clientAllowed := makeStringSet(parseRawJSONStrings(client.AllowedScopes))
	if len(clientAllowed) == 0 {
		clientAllowed = globalAllowed
	}

	if len(requested) == 0 {
		return []string{}, nil
	}

	for _, scope := range requested {
		if _, ok := globalAllowed[scope]; !ok {
			return nil, errorx.ErrOAuthInvalidScope
		}
		if _, ok := clientAllowed[scope]; !ok {
			return nil, errorx.ErrOAuthInvalidScope
		}
	}
	return requested, nil
}

func (s *OAuthService) signOAuthAccessToken(client *entity.OAuthClient, userID *string, scopes []string, tokenUse string) (string, time.Time, string, error) {
	active, err := s.secrets.GetActive(security.SecretFamilyOAuthAccess)
	if err != nil {
		return "", time.Time{}, "", errorx.ErrTokenGeneration
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.oauthAccessTTL())
	tokenID, err := id.Generate()
	if err != nil {
		return "", time.Time{}, "", errorx.ErrTokenGeneration
	}

	sub := strings.TrimSpace(derefString(userID))
	if sub == "" {
		sub = strings.TrimSpace(client.ClientID)
	}

	token, err := security.Sign(security.Claims{
		Subject:   sub,
		ClientID:  client.ClientID,
		Scope:     strings.Join(scopes, " "),
		TokenUse:  tokenUse,
		Issuer:    strings.TrimSpace(s.cfg.App.PublicURL),
		Audience:  "oauth-resource",
		TokenID:   tokenID,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}, active.Value)
	if err != nil {
		return "", time.Time{}, "", errorx.ErrTokenGeneration
	}

	return token, expiresAt, tokenID, nil
}

func (s *OAuthService) parseOAuthAccessToken(raw string) (security.Claims, error) {
	candidates, err := s.secrets.GetCandidates(security.SecretFamilyOAuthAccess)
	if err != nil {
		return security.Claims{}, err
	}
	for _, candidate := range candidates {
		claims, parseErr := security.Parse(raw, candidate.Value)
		if parseErr == nil {
			return claims, nil
		}
	}
	return security.Claims{}, errorx.ErrOAuthInvalidGrant
}

func (s *OAuthService) generateClientSecret() (string, error) {
	active, err := s.secrets.GetActive(security.SecretFamilyOAuthRefresh)
	if err != nil {
		return "", errorx.ErrTokenGeneration
	}
	secret, err := security.GenerateToken(64, active.Value)
	if err != nil {
		return "", errorx.ErrTokenGeneration
	}
	return secret, nil
}

func (s *OAuthService) generateOAuthRefreshToken() (string, string, error) {
	active, err := s.secrets.GetActive(security.SecretFamilyOAuthRefresh)
	if err != nil {
		return "", "", errorx.ErrTokenGeneration
	}
	raw, err := security.GenerateToken(64, active.Value)
	if err != nil {
		return "", "", errorx.ErrTokenGeneration
	}
	hash, err := security.HashToken(raw, active.Value)
	if err != nil {
		return "", "", errorx.ErrTokenGeneration
	}
	return raw, hash, nil
}

func (s *OAuthService) hashWithCandidates(rawToken string, family string) []string {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil
	}

	candidates, err := s.secrets.GetCandidates(family)
	if err != nil || len(candidates) == 0 {
		return nil
	}

	out := make([]string, 0, len(candidates))
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		hash, err := security.HashToken(rawToken, candidate.Value)
		if err != nil {
			continue
		}
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		out = append(out, hash)
	}
	return out
}

func (s *OAuthService) lookupOAuthRefreshToken(ctx context.Context, rawToken string) (string, *entity.OAuthRefreshToken, error) {
	for _, hash := range s.hashWithCandidates(rawToken, security.SecretFamilyOAuthRefresh) {
		token, err := s.repo.GetRefreshTokenByHash(ctx, hash)
		if err != nil {
			if errors.Is(err, errorx.ErrOAuthInvalidGrant) {
				continue
			}
			return "", nil, err
		}
		if token != nil {
			return hash, token, nil
		}
	}
	return "", nil, errorx.ErrOAuthInvalidGrant
}

func (s *OAuthService) blacklistAccessToken(ctx context.Context, claims security.Claims) {
	if s == nil || s.rdb == nil || strings.TrimSpace(claims.TokenID) == "" {
		return
	}

	ttl := time.Until(time.Unix(claims.ExpiresAt, 0).UTC())
	if ttl <= 0 {
		return
	}

	key := oauthAccessBlacklistKey + strings.TrimSpace(claims.TokenID)
	_ = s.rdb.Set(ctx, key, "1", ttl).Err()
}

func (s *OAuthService) isAccessTokenRevoked(ctx context.Context, tokenID string) bool {
	if s == nil || s.rdb == nil || strings.TrimSpace(tokenID) == "" {
		return false
	}

	exists, err := s.rdb.Exists(ctx, oauthAccessBlacklistKey+strings.TrimSpace(tokenID)).Result()
	if err != nil {
		return false
	}
	return exists > 0
}

func (s *OAuthService) oauthAccessTTL() time.Duration {
	if s == nil || s.cfg == nil || s.cfg.Security.AccessSecretTTL <= 0 {
		return 15 * time.Minute
	}
	return s.cfg.Security.AccessSecretTTL
}

func (s *OAuthService) oauthRefreshTTL() time.Duration {
	if s == nil || s.cfg == nil || s.cfg.Security.RefreshTokenTTL <= 0 {
		return 7 * 24 * time.Hour
	}
	return s.cfg.Security.RefreshTokenTTL
}

func (s *OAuthService) oauthAuthCodeTTL() time.Duration {
	if s == nil || s.cfg == nil || s.cfg.Security.OAuthAuthorizationCodeTTL <= 0 {
		return 5 * time.Minute
	}
	return s.cfg.Security.OAuthAuthorizationCodeTTL
}

func buildOAuthRedirectURI(base string, values map[string]string) string {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return strings.TrimSpace(base)
	}

	q := u.Query()
	for k, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func normalizeRedirectURIs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errorx.ErrOAuthInvalidRedirectURI
	}

	set := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, item := range values {
		u, err := url.Parse(strings.TrimSpace(item))
		if err != nil || u == nil || strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
			return nil, errorx.ErrOAuthInvalidRedirectURI
		}
		normalized := u.String()
		if _, ok := set[normalized]; ok {
			continue
		}
		set[normalized] = struct{}{}
		result = append(result, normalized)
	}
	if len(result) == 0 {
		return nil, errorx.ErrOAuthInvalidRedirectURI
	}
	sort.Strings(result)
	return result, nil
}

func normalizeScopeSlice(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		scope := strings.TrimSpace(value)
		if scope == "" {
			continue
		}
		set[scope] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for scope := range set {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

func parseRawJSONStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil
	}
	return normalizeScopeSlice(values)
}

func parseRawJSONStringsPtr(raw *json.RawMessage) []string {
	if raw == nil {
		return nil
	}
	return parseRawJSONStrings(*raw)
}

func mustMarshalJSON(v any, fallback []byte) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return raw
}

func mustMarshalJSONPtr(v any) *json.RawMessage {
	raw := mustMarshalJSON(v, []byte("[]"))
	return &raw
}

func rawJSONPtr(raw []byte) *json.RawMessage {
	if len(raw) == 0 {
		value := json.RawMessage("[]")
		return &value
	}
	value := json.RawMessage(raw)
	return &value
}

func isSubset(subset, superset []string) bool {
	if len(subset) == 0 {
		return true
	}
	set := makeStringSet(superset)
	for _, item := range subset {
		if _, ok := set[item]; !ok {
			return false
		}
	}
	return true
}

func makeStringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return set
}

func containsString(values []string, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}

func ptrString(v string) *string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return &v
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func hashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(verifier)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
