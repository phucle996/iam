package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"controlplane/internal/domain/entity"
	domainsvc "controlplane/internal/domain/service"
	reqdto "controlplane/internal/transport/http/request"
	"controlplane/pkg/apires"
	"controlplane/pkg/errorx"
	"controlplane/pkg/logger"

	"github.com/gin-gonic/gin"
)

// RbacHandler provides admin endpoints for roles and permissions.
// All routes must be protected by Access + RequireLevel middleware.
type RbacHandler struct {
	svc domainsvc.RbacService
}

func NewRbacHandler(svc domainsvc.RbacService) *RbacHandler {
	return &RbacHandler{svc: svc}
}

// ── Roles ─────────────────────────────────────────────────────────────────────

// @Router /api/v1/admin/rbac/roles [get]
// @Tags RBAC
// @Summary List roles
// @Description List roles
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
func (h *RbacHandler) ListRoles(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	roles, err := h.svc.ListRoles(ctx)
	if err != nil {
		logger.HandlerError(c, "iam.rbac.list-roles", err)
		apires.RespondInternalError(c, "failed to list roles")
		return
	}
	logger.HandlerInfo(c, "iam.rbac.list-roles", "roles listed")
	apires.RespondSuccess(c, roles, "ok")
}

// @Router /api/v1/admin/rbac/roles/:id [get]
// @Tags RBAC
// @Summary Get role
// @Description Get role
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
func (h *RbacHandler) GetRole(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	rp, err := h.svc.GetRole(ctx, c.Param("id"))
	if err != nil {
		logger.HandlerError(c, "iam.rbac.get-role", err)
		h.mapError(c, err)
		return
	}
	logger.HandlerInfo(c, "iam.rbac.get-role", "role fetched")
	apires.RespondSuccess(c, rp, "ok")
}

// @Router /api/v1/admin/rbac/roles [post]
// @Tags RBAC
// @Summary Create role
// @Description Create role
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *RbacHandler) CreateRole(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req reqdto.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	role := &entity.Role{
		Name:        req.Name,
		Level:       req.Level,
		Description: req.Description,
	}
	if err := h.svc.CreateRole(ctx, role); err != nil {
		logger.HandlerError(c, "iam.rbac.create-role", err)
		h.mapError(c, err)
		return
	}

	logger.HandlerInfo(c, "iam.rbac.create-role", "role created")
	c.JSON(http.StatusCreated, gin.H{"role": role, "message": "role created"})
}

// @Router /api/v1/admin/rbac/roles/:id [patch]
// @Tags RBAC
// @Summary Update role
// @Description Update role
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *RbacHandler) UpdateRole(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req reqdto.UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	role := &entity.Role{
		ID:          c.Param("id"),
		Name:        req.Name,
		Level:       req.Level,
		Description: req.Description,
	}
	if err := h.svc.UpdateRole(ctx, role); err != nil {
		logger.HandlerError(c, "iam.rbac.update-role", err)
		h.mapError(c, err)
		return
	}
	logger.HandlerInfo(c, "iam.rbac.update-role", "role updated — cache invalidated")
	apires.RespondSuccess(c, nil, "role updated — cache invalidated")
}

// @Router /api/v1/admin/rbac/roles/:id [delete]
// @Tags RBAC
// @Summary Delete role
// @Description Delete role
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
func (h *RbacHandler) DeleteRole(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if err := h.svc.DeleteRole(ctx, c.Param("id")); err != nil {
		logger.HandlerError(c, "iam.rbac.delete-role", err)
		h.mapError(c, err)
		return
	}
	logger.HandlerInfo(c, "iam.rbac.delete-role", "role deleted")
	apires.RespondSuccess(c, nil, "role deleted")
}

// ── Permissions ───────────────────────────────────────────────────────────────

// @Router /api/v1/admin/rbac/permissions [get]
// @Tags RBAC
// @Summary List permissions
// @Description List permissions
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
func (h *RbacHandler) ListPermissions(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	perms, err := h.svc.ListPermissions(ctx)
	if err != nil {
		logger.HandlerError(c, "iam.rbac.list-permissions", err)
		apires.RespondInternalError(c, "failed to list permissions")
		return
	}
	logger.HandlerInfo(c, "iam.rbac.list-permissions", "permissions listed")
	apires.RespondSuccess(c, perms, "ok")
}

// @Router /api/v1/admin/rbac/roles/:id/permissions [post]
// @Tags RBAC
// @Summary Assign permission
// @Description Assign permission
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
func (h *RbacHandler) AssignPermission(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var req reqdto.AssignPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apires.RespondBadRequest(c, "invalid request payload")
		return
	}

	if err := h.svc.AssignPermission(ctx, c.Param("id"), req.PermissionID); err != nil {
		logger.HandlerError(c, "iam.rbac.assign-permission", err)
		h.mapError(c, err)
		return
	}
	logger.HandlerInfo(c, "iam.rbac.assign-permission", "permission assigned — cache invalidated")
	apires.RespondSuccess(c, nil, "permission assigned — cache invalidated")
}

// @Router /api/v1/admin/rbac/roles/:id/permissions/:perm_id [delete]
// @Tags RBAC
// @Summary Revoke permission
// @Description Revoke permission
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
func (h *RbacHandler) RevokePermission(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if err := h.svc.RevokePermission(ctx, c.Param("id"), c.Param("perm_id")); err != nil {
		logger.HandlerError(c, "iam.rbac.revoke-permission", err)
		h.mapError(c, err)
		return
	}
	logger.HandlerInfo(c, "iam.rbac.revoke-permission", "permission revoked — cache invalidated")
	apires.RespondSuccess(c, nil, "permission revoked — cache invalidated")
}

// @Router /api/v1/admin/rbac/cache/invalidate [post]
// @Tags RBAC
// @Summary Invalidate cache
// @Description Invalidate cache
// @Accept json
// @Produce json
// @Success 200 {object} response.Response
// @Failure 500 {object} response.Response
func (h *RbacHandler) InvalidateAll(c *gin.Context) {
	h.svc.InvalidateAll(c.Request.Context())
	logger.HandlerWarn(c, "iam.rbac.cache-invalidate", nil, "entire rbac cache flushed")
	apires.RespondSuccess(c, nil, "rbac cache flushed")
}

// ── error mapping ─────────────────────────────────────────────────────────────

func (h *RbacHandler) mapError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errorx.ErrRoleNotFound):
		apires.RespondNotFound(c, "role not found")
	case errors.Is(err, errorx.ErrPermissionNotFound):
		apires.RespondNotFound(c, "permission not found")
	case errors.Is(err, errorx.ErrRoleAlreadyExists):
		apires.RespondConflict(c, "role already exists")
	default:
		apires.RespondInternalError(c, "rbac operation failed")
	}
}
