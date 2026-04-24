package handler

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"iam/internal/domain/entity"
	domainsvc "iam/internal/domain/service"
	"iam/internal/transport/http/middleware"
	reqdto "iam/internal/transport/http/request"
	"iam/pkg/apires"
	response "iam/pkg/apires"
	"iam/pkg/errorx"
	"iam/pkg/logger"

	"github.com/gin-gonic/gin"
)

// MfaHandler handles all MFA-related HTTP endpoints.
type MfaHandler struct {
	mfaSvc   domainsvc.MfaService
	tokenSvc domainsvc.TokenService
}

var mfaMethodPool sync.Pool

func NewMfaHandler(
	mfaSvc domainsvc.MfaService,
	tokenSvc domainsvc.TokenService,
) *MfaHandler {
	return &MfaHandler{
		mfaSvc:   mfaSvc,
		tokenSvc: tokenSvc,
	}
}

// ── Challenge flow ────────────────────────────────────────────────────────────

// @Router /api/v1/auth/mfa/verify [post]
// @Tags MFA
// @Summary Verify MFA
// @Description Verify MFA
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *MfaHandler) Verify(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var req reqdto.MfaVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.mfa.verify", err, "invalid payload")
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	// Delegate full verification to MfaService.
	userID, deviceID, err := h.mfaSvc.Verify(ctx, req.ChallengeID, req.Method, req.Code)
	if err != nil {
		logger.HandlerError(c, "iam.mfa.verify", err)
		h.mapMfaError(c, err)
		return
	}

	// MFA passed — load user + device, then issue token pair via TokenService.
	// We pass a minimal entity.User with just the ID; TokenService.IssueAfterLogin
	// reconstructs full claims from its own fetch inside issueAccessToken.
	tokenResult, err := h.tokenSvc.IssueForMFA(ctx, userID, deviceID)
	if err != nil {
		logger.HandlerError(c, "iam.mfa.verify", err)
		apires.RespondInternalError(c, "token issuance failed")
		return
	}

	setSessionCookies(c, tokenResult.AccessToken, tokenResult.RefreshToken, tokenResult.DeviceID, tokenResult.AccessTokenExpiresAt, tokenResult.RefreshTokenExpiresAt)
	logger.HandlerInfo(c, "iam.mfa.verify", "mfa verified — cookies issued")
	c.AbortWithStatus(http.StatusNoContent)
}

// ── Self-service (requires access token) ─────────────────────────────────────

// @Router /api/v1/me/mfa [get]
// @Tags MFA
// @Summary List MFA methods
// @Description List MFA methods
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
func (h *MfaHandler) ListMethods(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := c.GetString(middleware.CtxKeyUserID)
	methods, err := h.mfaSvc.ListMethods(ctx, userID)
	if err != nil {
		logger.HandlerError(c, "iam.mfa.list-methods", err)
		response.RespondInternalError(c, "failed to list mfa methods")
		return
	}

	logger.HandlerInfo(c, "iam.mfa.list-methods", "mfa methods listed")

	// Reuse response slice container for frequent MFA settings reads.
	borrowMethods := func(minCap int) []*entity.MfaSetting {
		if minCap < iamPooledSliceDefaultCap {
			minCap = iamPooledSliceDefaultCap
		}
		if pooled, ok := mfaMethodPool.Get().([]*entity.MfaSetting); ok && cap(pooled) >= minCap {
			return pooled[:0]
		}
		return make([]*entity.MfaSetting, 0, minCap)
	}
	releaseMethods := func(items []*entity.MfaSetting) {
		if cap(items) == 0 || cap(items) > iamPooledSliceMaxCap {
			return
		}
		full := items[:cap(items)]
		clear(full)
		mfaMethodPool.Put(full[:0])
	}

	items := borrowMethods(len(methods))
	items = append(items, methods...)
	defer releaseMethods(items)

	response.RespondSuccess(c, items, "ok")
}

// @Router /api/v1/me/mfa/totp/enroll [post]
// @Tags MFA
// @Summary Enroll TOTP
// @Description Enroll TOTP
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *MfaHandler) EnrollTOTP(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req reqdto.MfaEnrollTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondBadRequest(c, "invalid request payload")
		return
	}

	userID := c.GetString(middleware.CtxKeyUserID)
	settingID, provisioningURI, err := h.mfaSvc.EnrollTOTP(ctx, userID, req.DeviceName)
	if err != nil {
		logger.HandlerError(c, "iam.mfa.enroll-totp", err)
		apires.RespondInternalError(c, "totp enrollment failed")
		return
	}

	logger.HandlerInfo(c, "iam.mfa.enroll-totp", "totp enrolled")
	apires.RespondSuccess(c, gin.H{
		"setting_id":       settingID,
		"provisioning_uri": provisioningURI,
	}, "scan the QR code and confirm with a valid code")
}

// @Router /api/v1/me/mfa/totp/confirm [post]
// @Tags MFA
// @Summary Confirm TOTP
// @Description Confirm TOTP
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *MfaHandler) ConfirmTOTP(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req reqdto.MfaConfirmTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	userID := c.GetString(middleware.CtxKeyUserID)
	if err := h.mfaSvc.ConfirmTOTP(ctx, userID, req.SettingID, req.Code); err != nil {
		logger.HandlerError(c, "iam.mfa.confirm-totp", err)
		h.mapMfaError(c, err)
		return
	}

	logger.HandlerInfo(c, "iam.mfa.confirm-totp", "totp confirmed and enabled")
	apires.RespondSuccess(c, nil, "totp enabled")
}

// EnableMethod PATCH /api/v1/me/mfa/:setting_id/enable
func (h *MfaHandler) EnableMethod(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := c.GetString(middleware.CtxKeyUserID)
	settingID := c.Param("setting_id")
	if err := h.mfaSvc.EnableMethod(ctx, userID, settingID); err != nil {
		logger.HandlerError(c, "iam.mfa.enable", err)
		h.mapMfaError(c, err)
		return
	}
	logger.HandlerInfo(c, "iam.mfa.enable", "mfa method enabled")
	apires.RespondSuccess(c, nil, "method enabled")
}

// DisableMethod PATCH /api/v1/me/mfa/:setting_id/disable
func (h *MfaHandler) DisableMethod(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := c.GetString(middleware.CtxKeyUserID)
	settingID := c.Param("setting_id")
	if err := h.mfaSvc.DisableMethod(ctx, userID, settingID); err != nil {
		logger.HandlerError(c, "iam.mfa.disable", err)
		h.mapMfaError(c, err)
		return
	}
	logger.HandlerInfo(c, "iam.mfa.disable", "mfa method disabled")
	apires.RespondSuccess(c, nil, "method disabled")
}

// DeleteMethod DELETE /api/v1/me/mfa/:setting_id
func (h *MfaHandler) DeleteMethod(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := c.GetString(middleware.CtxKeyUserID)
	settingID := c.Param("setting_id")
	if err := h.mfaSvc.DeleteMethod(ctx, userID, settingID); err != nil {
		logger.HandlerError(c, "iam.mfa.delete", err)
		h.mapMfaError(c, err)
		return
	}
	logger.HandlerInfo(c, "iam.mfa.delete", "mfa method removed")
	apires.RespondSuccess(c, nil, "method removed")
}

// GenerateRecoveryCodes POST /api/v1/me/mfa/recovery-codes
func (h *MfaHandler) GenerateRecoveryCodes(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := c.GetString(middleware.CtxKeyUserID)
	codes, err := h.mfaSvc.GenerateRecoveryCodes(ctx, userID)
	if err != nil {
		logger.HandlerError(c, "iam.mfa.recovery-codes", err)
		apires.RespondInternalError(c, "recovery code generation failed")
		return
	}

	logger.HandlerInfo(c, "iam.mfa.recovery-codes", "recovery codes generated")
	// Codes returned once only — client must save them.
	c.JSON(http.StatusOK, gin.H{
		"recovery_codes": codes,
		"warning":        "these codes are shown only once — save them now",
	})
}

// ── error mapping ─────────────────────────────────────────────────────────────

func (h *MfaHandler) mapMfaError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errorx.ErrMfaChallengeNotFound),
		errors.Is(err, errorx.ErrMfaChallengeInvalid):
		apires.RespondUnauthorized(c, "mfa challenge is invalid or has expired")
	case errors.Is(err, errorx.ErrMfaCodeInvalid):
		apires.RespondUnauthorized(c, "mfa code is incorrect")
	case errors.Is(err, errorx.ErrMfaCodeExpired):
		apires.RespondUnauthorized(c, "mfa code has expired — request a new one")
	case errors.Is(err, errorx.ErrMfaMethodNotAllowed):
		apires.RespondBadRequest(c, "the selected mfa method is not available for this challenge")
	case errors.Is(err, errorx.ErrMfaSettingNotFound):
		apires.RespondNotFound(c, "mfa setting not found")
	default:
		apires.RespondInternalError(c, "mfa operation failed")
	}
}
