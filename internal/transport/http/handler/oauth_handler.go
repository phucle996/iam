package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"iam/internal/domain/entity"
	domainsvc "iam/internal/domain/service"
	"iam/internal/transport/http/middleware"
	iamreq "iam/internal/transport/http/request"
	"iam/pkg/apires"
	"iam/pkg/errorx"
	"iam/pkg/logger"

	"github.com/gin-gonic/gin"
)

// OAuthHandler handles OAuth2.1 endpoints.
type OAuthHandler struct {
	oauthSvc domainsvc.OAuthService
}

func NewOAuthHandler(oauthSvc domainsvc.OAuthService) *OAuthHandler {
	return &OAuthHandler{oauthSvc: oauthSvc}
}

// Authorize prechecks OAuth authorize request and returns consent payload.
func (h *OAuthHandler) Authorize(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	userID := strings.TrimSpace(middleware.GetUserID(c))
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	var req iamreq.OAuthAuthorizeQuery
	if err := c.ShouldBindQuery(&req); err != nil {
		logger.HandlerWarn(c, "iam.oauth.authorize", err, "invalid authorize query")
		respondOAuthError(c, http.StatusBadRequest, "invalid_request", "invalid authorize request")
		return
	}

	result, err := h.oauthSvc.Authorize(ctx, &entity.OAuthAuthorizeRequest{
		UserID:              userID,
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})
	if err != nil {
		logger.HandlerError(c, "iam.oauth.authorize", err)
		h.mapOAuthError(c, err)
		return
	}

	apires.RespondSuccess(c, result, "oauth authorize precheck successful")
}

// Decide handles consent approval/denial and returns redirect URI.
func (h *OAuthHandler) Decide(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	userID := strings.TrimSpace(middleware.GetUserID(c))
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	var req iamreq.OAuthAuthorizeDecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.oauth.decision", err, "invalid consent payload")
		respondOAuthError(c, http.StatusBadRequest, "invalid_request", "invalid consent payload")
		return
	}

	result, err := h.oauthSvc.Decide(ctx, &entity.OAuthAuthorizeDecision{
		UserID:              userID,
		Approve:             req.Approve,
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})
	if err != nil {
		logger.HandlerError(c, "iam.oauth.decision", err)
		h.mapOAuthError(c, err)
		return
	}

	apires.RespondSuccess(c, result, "oauth consent decision accepted")
}

// Token exchanges OAuth grants for tokens.
func (h *OAuthHandler) Token(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req iamreq.OAuthTokenRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.HandlerWarn(c, "iam.oauth.token", err, "invalid token payload")
		respondOAuthError(c, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}

	clientID, clientSecret := resolveOAuthClientAuth(c, req.ClientID, req.ClientSecret)
	result, err := h.oauthSvc.Token(ctx, &entity.OAuthTokenRequest{
		GrantType:    req.GrantType,
		Code:         req.Code,
		RedirectURI:  req.RedirectURI,
		CodeVerifier: req.CodeVerifier,
		RefreshToken: req.RefreshToken,
		Scope:        req.Scope,
	}, clientID, clientSecret)
	if err != nil {
		logger.HandlerError(c, "iam.oauth.token", err)
		h.mapOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  result.AccessToken,
		"token_type":    result.TokenType,
		"expires_in":    result.ExpiresIn,
		"refresh_token": result.RefreshToken,
		"scope":         result.Scope,
	})
}

// Revoke revokes an OAuth access/refresh token.
func (h *OAuthHandler) Revoke(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req iamreq.OAuthRevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.HandlerWarn(c, "iam.oauth.revoke", err, "invalid revoke payload")
		respondOAuthError(c, http.StatusBadRequest, "invalid_request", "invalid revoke request")
		return
	}

	clientID, clientSecret := resolveOAuthClientAuth(c, req.ClientID, req.ClientSecret)
	if err := h.oauthSvc.Revoke(ctx, &entity.OAuthRevokeRequest{
		Token:         req.Token,
		TokenTypeHint: req.TokenTypeHint,
	}, clientID, clientSecret); err != nil {
		logger.HandlerError(c, "iam.oauth.revoke", err)
		h.mapOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

// Introspect checks whether an OAuth token is active.
func (h *OAuthHandler) Introspect(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req iamreq.OAuthIntrospectRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.HandlerWarn(c, "iam.oauth.introspect", err, "invalid introspect payload")
		respondOAuthError(c, http.StatusBadRequest, "invalid_request", "invalid introspection request")
		return
	}

	clientID, clientSecret := resolveOAuthClientAuth(c, req.ClientID, req.ClientSecret)
	result, err := h.oauthSvc.Introspect(ctx, &entity.OAuthIntrospectRequest{
		Token:         req.Token,
		TokenTypeHint: req.TokenTypeHint,
	}, clientID, clientSecret)
	if err != nil {
		logger.HandlerError(c, "iam.oauth.introspect", err)
		h.mapOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// AdminCreateClient creates a confidential OAuth client.
func (h *OAuthHandler) AdminCreateClient(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req iamreq.OAuthClientCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.oauth.admin.create_client", err, "invalid create client payload")
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	created, err := h.oauthSvc.CreateClient(ctx, &entity.OAuthClientCreateRequest{
		Name:          req.Name,
		RedirectURIs:  req.RedirectURIs,
		AllowedScopes: req.AllowedScopes,
		IsActive:      isActive,
		Metadata:      req.Metadata,
	})
	if err != nil {
		logger.HandlerError(c, "iam.oauth.admin.create_client", err)
		if errors.Is(err, errorx.ErrOAuthInvalidRedirectURI) || errors.Is(err, errorx.ErrOAuthInvalidScope) {
			apires.RespondBadRequest(c, "invalid request payload")
			return
		}
		apires.RespondInternalError(c, "internal server error")
		return
	}

	apires.RespondCreated(c, gin.H{
		"client":        created.Client,
		"client_secret": created.ClientSecret,
	}, "oauth client created")
}

// AdminListClients lists OAuth clients.
func (h *OAuthHandler) AdminListClients(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req iamreq.OAuthListClientsQuery
	_ = c.ShouldBindQuery(&req)

	clients, err := h.oauthSvc.ListClients(ctx, req.Limit, req.Offset)
	if err != nil {
		logger.HandlerError(c, "iam.oauth.admin.list_clients", err)
		apires.RespondInternalError(c, "internal server error")
		return
	}

	apires.RespondSuccess(c, clients, "oauth clients fetched")
}

// AdminGetClient gets one OAuth client.
func (h *OAuthHandler) AdminGetClient(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	clientID := strings.TrimSpace(c.Param("client_id"))
	if clientID == "" {
		apires.RespondBadRequest(c, "invalid client id")
		return
	}

	client, err := h.oauthSvc.GetClient(ctx, clientID)
	if err != nil {
		logger.HandlerError(c, "iam.oauth.admin.get_client", err)
		if errors.Is(err, errorx.ErrOAuthClientNotFound) {
			apires.RespondNotFound(c, "client not found")
			return
		}
		apires.RespondInternalError(c, "internal server error")
		return
	}

	apires.RespondSuccess(c, client, "oauth client fetched")
}

// AdminUpdateClient updates OAuth client metadata.
func (h *OAuthHandler) AdminUpdateClient(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	clientID := strings.TrimSpace(c.Param("client_id"))
	if clientID == "" {
		apires.RespondBadRequest(c, "invalid client id")
		return
	}

	var req iamreq.OAuthClientUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.oauth.admin.update_client", err, "invalid update payload")
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	updated, err := h.oauthSvc.UpdateClient(ctx, &entity.OAuthClientUpdateRequest{
		ClientID:      clientID,
		Name:          req.Name,
		RedirectURIs:  req.RedirectURIs,
		AllowedScopes: req.AllowedScopes,
		IsActive:      req.IsActive,
		Metadata:      req.Metadata,
	})
	if err != nil {
		logger.HandlerError(c, "iam.oauth.admin.update_client", err)
		switch {
		case errors.Is(err, errorx.ErrOAuthClientNotFound):
			apires.RespondNotFound(c, "client not found")
		case errors.Is(err, errorx.ErrOAuthInvalidRequest),
			errors.Is(err, errorx.ErrOAuthInvalidScope),
			errors.Is(err, errorx.ErrOAuthInvalidRedirectURI):
			apires.RespondBadRequest(c, "invalid request payload")
		default:
			apires.RespondInternalError(c, "internal server error")
		}
		return
	}

	apires.RespondSuccess(c, updated, "oauth client updated")
}

// AdminDeleteClient deletes OAuth client.
func (h *OAuthHandler) AdminDeleteClient(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	clientID := strings.TrimSpace(c.Param("client_id"))
	if clientID == "" {
		apires.RespondBadRequest(c, "invalid client id")
		return
	}

	if err := h.oauthSvc.DeleteClient(ctx, clientID); err != nil {
		logger.HandlerError(c, "iam.oauth.admin.delete_client", err)
		if errors.Is(err, errorx.ErrOAuthClientNotFound) {
			apires.RespondNotFound(c, "client not found")
			return
		}
		apires.RespondInternalError(c, "internal server error")
		return
	}

	c.AbortWithStatus(http.StatusNoContent)
}

// AdminRotateClientSecret rotates client secret and returns plaintext once.
func (h *OAuthHandler) AdminRotateClientSecret(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	clientID := strings.TrimSpace(c.Param("client_id"))
	if clientID == "" {
		apires.RespondBadRequest(c, "invalid client id")
		return
	}

	result, err := h.oauthSvc.RotateClientSecret(ctx, clientID)
	if err != nil {
		logger.HandlerError(c, "iam.oauth.admin.rotate_client_secret", err)
		if errors.Is(err, errorx.ErrOAuthClientNotFound) {
			apires.RespondNotFound(c, "client not found")
			return
		}
		apires.RespondInternalError(c, "internal server error")
		return
	}

	apires.RespondSuccess(c, gin.H{
		"client":        result.Client,
		"client_secret": result.ClientSecret,
	}, "oauth client secret rotated")
}

// AdminRevokeGrant revokes grant for a user and client.
func (h *OAuthHandler) AdminRevokeGrant(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	clientID := strings.TrimSpace(c.Param("client_id"))
	if clientID == "" {
		apires.RespondBadRequest(c, "invalid client id")
		return
	}

	var req iamreq.OAuthAdminRevokeGrantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	if err := h.oauthSvc.AdminRevokeGrant(ctx, req.UserID, clientID); err != nil {
		logger.HandlerError(c, "iam.oauth.admin.revoke_grant", err)
		if errors.Is(err, errorx.ErrOAuthGrantNotFound) || errors.Is(err, errorx.ErrOAuthClientNotFound) {
			apires.RespondNotFound(c, "grant not found")
			return
		}
		apires.RespondInternalError(c, "internal server error")
		return
	}

	c.AbortWithStatus(http.StatusNoContent)
}

// ListMyGrants lists current user's OAuth grants.
func (h *OAuthHandler) ListMyGrants(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	userID := strings.TrimSpace(middleware.GetUserID(c))
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	grants, err := h.oauthSvc.ListMyGrants(ctx, userID)
	if err != nil {
		logger.HandlerError(c, "iam.oauth.me.list_grants", err)
		apires.RespondInternalError(c, "internal server error")
		return
	}

	apires.RespondSuccess(c, grants, "oauth grants fetched")
}

// RevokeMyGrant revokes current user's grant for one client.
func (h *OAuthHandler) RevokeMyGrant(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	userID := strings.TrimSpace(middleware.GetUserID(c))
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	clientID := strings.TrimSpace(c.Param("client_id"))
	if clientID == "" {
		apires.RespondBadRequest(c, "invalid client id")
		return
	}

	if err := h.oauthSvc.RevokeMyGrant(ctx, userID, clientID); err != nil {
		logger.HandlerError(c, "iam.oauth.me.revoke_grant", err)
		if errors.Is(err, errorx.ErrOAuthGrantNotFound) || errors.Is(err, errorx.ErrOAuthClientNotFound) {
			apires.RespondNotFound(c, "grant not found")
			return
		}
		apires.RespondInternalError(c, "internal server error")
		return
	}

	c.AbortWithStatus(http.StatusNoContent)
}

func (h *OAuthHandler) mapOAuthError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errorx.ErrOAuthInvalidRequest):
		respondOAuthError(c, http.StatusBadRequest, "invalid_request", "invalid request")
	case errors.Is(err, errorx.ErrOAuthInvalidClient),
		errors.Is(err, errorx.ErrOAuthClientInactive),
		errors.Is(err, errorx.ErrOAuthClientNotFound):
		c.Header("WWW-Authenticate", `Basic realm="oauth"`)
		respondOAuthError(c, http.StatusUnauthorized, "invalid_client", "client authentication failed")
	case errors.Is(err, errorx.ErrOAuthInvalidScope):
		respondOAuthError(c, http.StatusBadRequest, "invalid_scope", "requested scope is invalid")
	case errors.Is(err, errorx.ErrOAuthUnsupportedGrantType):
		respondOAuthError(c, http.StatusBadRequest, "unsupported_grant_type", "grant type is not supported")
	case errors.Is(err, errorx.ErrOAuthUnsupportedRespType):
		respondOAuthError(c, http.StatusBadRequest, "unsupported_response_type", "response type is not supported")
	case errors.Is(err, errorx.ErrOAuthInvalidRedirectURI):
		respondOAuthError(c, http.StatusBadRequest, "invalid_request", "redirect uri is invalid")
	case errors.Is(err, errorx.ErrOAuthInvalidPKCE),
		errors.Is(err, errorx.ErrOAuthCodeNotFound),
		errors.Is(err, errorx.ErrOAuthCodeConsumed),
		errors.Is(err, errorx.ErrOAuthCodeExpired),
		errors.Is(err, errorx.ErrOAuthInvalidGrant),
		errors.Is(err, errorx.ErrOAuthTokenExpired),
		errors.Is(err, errorx.ErrOAuthReplayDetected):
		respondOAuthError(c, http.StatusBadRequest, "invalid_grant", "grant is invalid or expired")
	case errors.Is(err, errorx.ErrOAuthAccessDenied):
		respondOAuthError(c, http.StatusForbidden, "access_denied", "request is not allowed")
	default:
		respondOAuthError(c, http.StatusInternalServerError, "server_error", "oauth server error")
	}
}

func resolveOAuthClientAuth(c *gin.Context, payloadClientID, payloadClientSecret string) (string, string) {
	if c != nil && c.Request != nil {
		if id, secret, ok := c.Request.BasicAuth(); ok {
			if strings.TrimSpace(id) != "" && strings.TrimSpace(secret) != "" {
				return id, secret
			}
		}
	}

	return strings.TrimSpace(payloadClientID), strings.TrimSpace(payloadClientSecret)
}

func respondOAuthError(c *gin.Context, status int, code, description string) {
	if c == nil {
		return
	}
	c.JSON(status, gin.H{
		"error":             strings.TrimSpace(code),
		"error_description": strings.TrimSpace(description),
	})
}
