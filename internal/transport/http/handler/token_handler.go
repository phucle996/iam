package handler

import (
	"context"
	"controlplane/internal/domain/entity"
	domainsvc "controlplane/internal/domain/service"
	"controlplane/internal/observability"
	reqdto "controlplane/internal/transport/http/request"
	"controlplane/pkg/apires"
	response "controlplane/pkg/apires"
	"controlplane/pkg/errorx"
	"controlplane/pkg/logger"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// TokenHandler handles refresh-token issuance and rotation.
type TokenHandler struct {
	tokenSvc domainsvc.TokenService
}

func NewTokenHandler(tokenSvc domainsvc.TokenService) *TokenHandler {
	return &TokenHandler{tokenSvc: tokenSvc}
}

// Refresh POST /api/v1/auth/refresh
//
// Flow:
//  1. Bind and validate the signed request body.
//  2. Delegate to TokenService.Rotate which:
//     a. Verifies the device signature against the stored public key.
//     b. Revokes the presented refresh token.
//     c. Issues a new access token + refresh token.
//  3. Set the new tokens as HttpOnly cookies and return 204 No Content.

// @Router /api/v1/auth/refresh [post]
// @Tags Token
// @Summary Refresh token
// @Description Refresh token
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
func (h *TokenHandler) Refresh(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	refreshSuccess := false
	defer func() {
		if prom := observability.CurrentPrometheus(); prom != nil {
			prom.ObserveAuthAttempt("refresh", refreshSuccess)
		}
	}()

	var req reqdto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.token.refresh", err, "invalid payload")
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	refreshTokenCookie, err := c.Cookie("refresh_token")
	if err != nil {
		logger.HandlerWarn(c, "iam.token.refresh", err, "refresh token cookie not found")
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	deviceIDCookie, err := c.Cookie("device_id")
	if err != nil {
		logger.HandlerWarn(c, "iam.token.refresh", err, "device id cookie not found")
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	if strings.TrimSpace(req.DeviceID) != strings.TrimSpace(deviceIDCookie) {
		logger.HandlerWarn(c, "iam.token.refresh", nil, "device id mismatch")
		apires.RespondUnauthorized(c, "refresh token is invalid or expired")
		return
	}

	result, err := h.tokenSvc.Rotate(ctx, &entity.RotateToken{
		RawRefreshToken: refreshTokenCookie,
		DeviceID:        deviceIDCookie,
		JTI:             req.JTI,
		IssuedAt:        req.IssuedAt,
		HTM:             req.HTM,
		HTU:             req.HTU,
		TokenHash:       req.TokenHash,
		Signature:       req.Signature,
	})
	if err != nil {
		logger.HandlerError(c, "iam.token.refresh", err)
		if errors.Is(err, errorx.ErrRefreshSignatureReplay) {
			if prom := observability.CurrentPrometheus(); prom != nil {
				prom.IncRefreshReplay()
			}
		}
		switch {
		case errors.Is(err, errorx.ErrRefreshTokenInvalid),
			errors.Is(err, errorx.ErrRefreshTokenMismatch),
			errors.Is(err, errorx.ErrRefreshSignatureReplay),
			errors.Is(err, errorx.ErrRefreshDeviceUnbound),
			errors.Is(err, errorx.ErrRefreshSignatureInvalid),
			errors.Is(err, errorx.ErrRefreshSignatureExpired):
			response.RespondUnauthorized(c, "refresh token is invalid or expired")
		default:
			response.RespondInternalError(c, "internal server error")
		}
		return
	}

	setSessionCookies(c, result.AccessToken, result.RefreshToken, result.DeviceID, result.AccessTokenExpiresAt, result.RefreshTokenExpiresAt)
	refreshSuccess = true

	logger.HandlerInfo(c, "iam.token.refresh", "token rotated")
	c.AbortWithStatus(http.StatusNoContent)
}
