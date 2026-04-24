package handler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"iam/internal/domain/entity"
	domainsvc "iam/internal/domain/service"
	"iam/internal/transport/http/middleware"
	iam_reqdto "iam/internal/transport/http/request"
	"iam/pkg/apires"
	"iam/pkg/errorx"
	"iam/pkg/logger"

	"github.com/gin-gonic/gin"
)

// DeviceHandler handles device management endpoints.
type DeviceHandler struct {
	deviceSvc domainsvc.DeviceService
}

var deviceListPool sync.Pool

func NewDeviceHandler(deviceSvc domainsvc.DeviceService) *DeviceHandler {
	return &DeviceHandler{deviceSvc: deviceSvc}
}

// @Summary Issue challenge
// @Description Issue challenge for device
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 400 {object} iam_respdto.Error
// @Router /devices/challenge [post]
func (h *DeviceHandler) IssueChallenge(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := middleware.GetUserID(c)
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	deviceID := strings.TrimSpace(middleware.GetDeviceID(c))
	if deviceID == "" {
		logger.HandlerWarn(c, "iam.device.challenge", nil, "device id is required")
		apires.RespondBadRequest(c, "device id is required")
		return
	}

	ch, err := h.deviceSvc.IssueChallenge(ctx, userID, deviceID)
	if err != nil {
		logger.HandlerError(c, "iam.device.challenge", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.device.challenge", "challenge issued")
	apires.RespondSuccess(c, gin.H{
		"challenge_id": ch.ChallengeID,
		"nonce":        ch.Nonce,
		"expires_at":   ch.ExpiresAt,
	}, "challenge issued")
}

// @Summary Verify proof
// @Description Verify proof for device
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 400 {object} iam_respdto.Error
// @Router /devices/verify [post]
func (h *DeviceHandler) VerifyProof(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req iam_reqdto.VerifyProofRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.device.verify", err, "invalid payload")
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	deviceID := strings.TrimSpace(middleware.GetDeviceID(c))
	if deviceID == "" {
		logger.HandlerWarn(c, "iam.device.verify", nil, "device id is required")
		apires.RespondBadRequest(c, "device id is required")
		return
	}

	proof := &entity.DeviceProof{
		ChallengeID: req.ChallengeID,
		DeviceID:    deviceID,
		Signature:   req.Signature,
	}

	if err := h.deviceSvc.VerifyProof(ctx, proof); err != nil {
		logger.HandlerError(c, "iam.device.verify", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.device.verify", "proof verified")
	apires.RespondSuccess(c, nil, "device proof verified")
}

// @Summary Rotate key
// @Description Rotate key for device
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 400 {object} iam_respdto.Error
// @Router /devices/rotate-key [post]
func (h *DeviceHandler) RotateKey(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := middleware.GetUserID(c)
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	var req iam_reqdto.RotateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.device.rotate-key", err, "invalid payload")
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	deviceID := strings.TrimSpace(middleware.GetDeviceID(c))
	if deviceID == "" {
		logger.HandlerWarn(c, "iam.device.rotate-key", nil, "device id is required")
		apires.RespondBadRequest(c, "device id is required")
		return
	}

	if err := h.deviceSvc.RotateKey(ctx, userID, deviceID, req.NewPublicKey, req.NewAlgorithm); err != nil {
		logger.HandlerError(c, "iam.device.rotate-key", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.device.rotate-key", "device key rotated")
	apires.RespondSuccess(c, nil, "device key rotated")
}

// @Summary Rebind device
// @Description Rebind device
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 400 {object} iam_respdto.Error
// @Router /devices/rebind [post]
func (h *DeviceHandler) Rebind(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := middleware.GetUserID(c)
	if strings.TrimSpace(userID) == "" {
		logger.HandlerWarn(c, "iam.device.rebind", nil, "user id is required")
		apires.RespondBadRequest(c, "user id is required")
		return
	}

	var req iam_reqdto.RebindRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.device.rebind", err, "invalid payload")
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	deviceID := strings.TrimSpace(middleware.GetDeviceID(c))
	if deviceID == "" {
		logger.HandlerWarn(c, "iam.device.rebind", nil, "device id is required")
		apires.RespondBadRequest(c, "device id is required")
		return
	}

	proof := &entity.DeviceProof{
		ChallengeID:  req.ChallengeID,
		DeviceID:     deviceID,
		Signature:    req.Signature,
		NewPublicKey: req.NewPublicKey,
		NewAlgorithm: req.NewAlgorithm,
	}
	if err := h.deviceSvc.Rebind(ctx, userID, proof); err != nil {
		logger.HandlerError(c, "iam.device.rebind", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.device.rebind", "device rebound")
	apires.RespondSuccess(c, nil, "device rebound successfully")
}

// @Summary Revoke device
// @Description Revoke device by ID
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 400 {object} iam_respdto.Error
// @Failure 404 {object} iam_respdto.Error
// @Router /devices/:id/revoke [delete]
func (h *DeviceHandler) RevokeDevice(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := middleware.GetUserID(c)
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	deviceID := strings.TrimSpace(c.Param("id"))
	if deviceID == "" {
		apires.RespondBadRequest(c, "device_id is required")
		return
	}

	if err := h.deviceSvc.Revoke(ctx, userID, deviceID); err != nil {
		logger.HandlerError(c, "iam.device.revoke", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.device.revoke", "device revoked")
	apires.RespondSuccess(c, nil, "device revoked")
}

// @Summary Quarantine device
// @Description Quarantine device by ID
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 400 {object} iam_respdto.Error
// @Failure 404 {object} iam_respdto.Error
// @Router /devices/:id/quarantine [post]
func (h *DeviceHandler) Quarantine(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	deviceID := strings.TrimSpace(c.Param("id"))
	if deviceID == "" {
		apires.RespondBadRequest(c, "device_id is required")
		return
	}

	if err := h.deviceSvc.Quarantine(ctx, deviceID); err != nil {
		logger.HandlerError(c, "iam.device.quarantine", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.device.quarantine", "device quarantined")
	apires.RespondSuccess(c, nil, "device quarantined")
}

// @Summary List devices for current user
// @Description List devices for current user
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 401 {object} iam_respdto.Error
// @Failure 500 {object} iam_respdto.Error
// @Router /me/devices [get]
func (h *DeviceHandler) ListMyDevices(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := middleware.GetUserID(c)
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	devices, err := h.deviceSvc.ListByUserID(ctx, userID)
	if err != nil {
		logger.HandlerError(c, "iam.device.list", err)
		apires.RespondInternalError(c, "failed to retrieve devices")
		return
	}

	// Reuse response slice container for the list-my-devices hot path.
	borrowDeviceList := func(minCap int) []*entity.Device {
		if minCap < iamPooledSliceDefaultCap {
			minCap = iamPooledSliceDefaultCap
		}
		if pooled, ok := deviceListPool.Get().([]*entity.Device); ok && cap(pooled) >= minCap {
			return pooled[:0]
		}
		return make([]*entity.Device, 0, minCap)
	}
	releaseDeviceList := func(items []*entity.Device) {
		if cap(items) == 0 || cap(items) > iamPooledSliceMaxCap {
			return
		}
		full := items[:cap(items)]
		clear(full)
		deviceListPool.Put(full[:0])
	}

	items := borrowDeviceList(len(devices))
	items = append(items, devices...)
	defer releaseDeviceList(items)

	apires.RespondSuccess(c, items, "ok")
}

// @Summary Revoke one device
// @Description Revoke one device for current user
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 401 {object} iam_respdto.Error
// @Router /me/devices/:id [delete]
func (h *DeviceHandler) RevokeOneDevice(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := middleware.GetUserID(c)
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	deviceID := strings.TrimSpace(c.Param("device_id"))
	if deviceID == "" {
		apires.RespondBadRequest(c, "device_id is required")
		return
	}

	if err := h.deviceSvc.RevokeOne(ctx, userID, deviceID); err != nil {
		logger.HandlerError(c, "iam.device.revoke-one", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.device.revoke-one", "device revoked")
	apires.RespondSuccess(c, nil, "device revoked")
}

// @Summary Revoke other devices
// @Description Revoke other devices for current user
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 401 {object} iam_respdto.Error
// @Router /me/devices/others [delete]
func (h *DeviceHandler) RevokeOtherDevices(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	userID := middleware.GetUserID(c)
	if userID == "" {
		apires.RespondUnauthorized(c, "unauthorized")
		return
	}

	deviceID := strings.TrimSpace(middleware.GetDeviceID(c))
	if deviceID == "" {
		logger.HandlerWarn(c, "iam.device.revoke-others", nil, "device_id is required")
		apires.RespondBadRequest(c, "device_id is required")
		return
	}

	n, err := h.deviceSvc.RevokeOthers(ctx, userID, deviceID)
	if err != nil {
		logger.HandlerError(c, "iam.device.revoke-others", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.device.revoke-others", "other devices revoked")
	apires.RespondSuccess(c, gin.H{"revoked": n}, "other devices revoked")
}

// ── Admin / internal ──────────────────────────────────────────────────────────

// @Summary Get device
// @Description Get device by ID
// @Tags device
// @Accept  json
// @Produce  json
// @Param id path string true "device ID"
// @Success 200 {object} iam_respdto.Device
// @Failure 400 {object} iam_respdto.Error
// @Failure 404 {object} iam_respdto.Error
// @Failure 500 {object} iam_respdto.Error
// @Router /admin/devices/:id [get]
func (h *DeviceHandler) AdminGetDevice(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	deviceID := strings.TrimSpace(c.Param("id"))
	if deviceID == "" {
		apires.RespondBadRequest(c, "device_id is required")
		return
	}

	device, err := h.deviceSvc.AdminGetByID(ctx, deviceID)
	if err != nil {
		logger.HandlerError(c, "iam.admin.device.get", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	apires.RespondSuccess(c, device, "")
}

// @Summary Force revoke device
// @Description Force revoke device by ID
// @Tags device
// @Accept  json
// @Produce  json
// @Param device_id path string true "device ID"
// @Success 200 {object} iam_respdto.Success
// @Failure 400 {object} iam_respdto.Error
// @Failure 404 {object} iam_respdto.Error
// @Failure 500 {object} iam_respdto.Error
// @Router /admin/devices/:id [delete]
func (h *DeviceHandler) AdminForceRevoke(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	deviceID := strings.TrimSpace(c.Param("id"))
	if deviceID == "" {
		apires.RespondBadRequest(c, "device_id is required")
		return
	}

	if err := h.deviceSvc.AdminRevoke(ctx, deviceID); err != nil {
		logger.HandlerError(c, "iam.admin.device.revoke", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.admin.device.revoke", "device force-revoked")
	apires.RespondSuccess(c, nil, "device force-revoked")
}

// @Summary Mark device as suspicious
// @Description Mark device as suspicious by ID
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 400 {object} iam_respdto.Error
// @Router /admin/devices/:id/suspicious [post]
func (h *DeviceHandler) AdminMarkSuspicious(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	deviceID := strings.TrimSpace(c.Param("id"))
	if deviceID == "" {
		apires.RespondBadRequest(c, "device_id is required")
		return
	}

	var req iam_reqdto.AdminMarkSuspiciousRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.admin.device.suspicious", err, "invalid payload")
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	if err := h.deviceSvc.MarkSuspicious(ctx, deviceID, req.Suspicious); err != nil {
		logger.HandlerError(c, "iam.admin.device.suspicious", err)
		switch {
		case errors.Is(err, errorx.ErrDeviceNotFound):
			apires.RespondNotFound(c, "device not found")
		case errors.Is(err, errorx.ErrDeviceForbidden):
			apires.RespondForbidden(c, "access denied")
		case errors.Is(err, errorx.ErrDeviceSuspicious):
			apires.RespondForbidden(c, "device is flagged suspicious")
		case errors.Is(err, errorx.ErrDeviceChallengeInvalid),
			errors.Is(err, errorx.ErrDeviceChallengeNotFound):
			apires.RespondBadRequest(c, "challenge invalid or expired")
		case errors.Is(err, errorx.ErrDeviceBindingRequired),
			errors.Is(err, errorx.ErrDeviceKeyInvalid):
			apires.RespondBadRequest(c, "invalid request payload")
		case errors.Is(err, errorx.ErrDeviceProofInvalid):
			apires.RespondBadRequest(c, "device proof invalid")
		case errors.Is(err, errorx.ErrDeviceKeyRotateFailed):
			apires.RespondInternalError(c, "key rotation failed")
		default:
			apires.RespondInternalError(c, "an unexpected error occurred")
		}
		return
	}

	logger.HandlerInfo(c, "iam.admin.device.suspicious", "device suspicious flag updated")
	apires.RespondSuccess(c, nil, "device updated")
}

// @Summary Cleanup stale devices
// @Description Cleanup stale devices
// @Tags device
// @Accept  json
// @Produce  json
// @Success 200 {object} iam_respdto.Success
// @Failure 400 {object} iam_respdto.Error
// @Failure 500 {object} iam_respdto.Error
// @Router /admin/devices/stale [delete]
func (h *DeviceHandler) AdminCleanupStale(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	var req iam_reqdto.CleanupStaleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.HandlerWarn(c, "iam.admin.device.cleanup", err, "invalid payload")
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	before := time.Now().UTC().AddDate(0, 0, -req.InactiveDays)
	n, err := h.deviceSvc.CleanupStale(ctx, before)
	if err != nil {
		logger.HandlerError(c, "iam.admin.device.cleanup", err)
		apires.RespondInternalError(c, "cleanup failed")
		return
	}

	logger.HandlerInfo(c, "iam.admin.device.cleanup", "stale devices cleaned")
	apires.RespondSuccess(c, gin.H{"removed": n}, "stale devices cleaned")
}
