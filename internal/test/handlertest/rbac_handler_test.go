package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"iam/internal/domain/entity"
	"iam/internal/transport/http/handler"
	"iam/internal/transport/http/middleware"
	reqdto "iam/internal/transport/http/request"
	"iam/pkg/errorx"
	"iam/pkg/logger"

	"github.com/gin-gonic/gin"
)

type stubRbacHandlerService struct {
	listRolesResult       []*entity.Role
	listRolesErr          error
	getRoleResult         *entity.RoleWithPermissions
	getRoleErr            error
	createRoleErr         error
	updateRoleErr         error
	deleteRoleErr         error
	listPermissionsResult []*entity.Permission
	listPermissionsErr    error
	assignPermErr         error
	revokePermErr         error
	invalidateCalled      bool
}

func (s *stubRbacHandlerService) LoadRole(ctx context.Context, role string) (middleware.RoleEntry, error) {
	return middleware.RoleEntry{}, nil
}
func (s *stubRbacHandlerService) InvalidateRole(ctx context.Context, role string) {}
func (s *stubRbacHandlerService) WarmUp(ctx context.Context) error                { return nil }
func (s *stubRbacHandlerService) ListRoles(ctx context.Context) ([]*entity.Role, error) {
	return s.listRolesResult, s.listRolesErr
}
func (s *stubRbacHandlerService) GetRole(ctx context.Context, id string) (*entity.RoleWithPermissions, error) {
	return s.getRoleResult, s.getRoleErr
}
func (s *stubRbacHandlerService) CreateRole(ctx context.Context, role *entity.Role) error {
	return s.createRoleErr
}
func (s *stubRbacHandlerService) UpdateRole(ctx context.Context, role *entity.Role) error {
	return s.updateRoleErr
}
func (s *stubRbacHandlerService) DeleteRole(ctx context.Context, id string) error {
	return s.deleteRoleErr
}
func (s *stubRbacHandlerService) ListPermissions(ctx context.Context) ([]*entity.Permission, error) {
	return s.listPermissionsResult, s.listPermissionsErr
}
func (s *stubRbacHandlerService) CreatePermission(ctx context.Context, perm *entity.Permission) error {
	return nil
}
func (s *stubRbacHandlerService) AssignPermission(ctx context.Context, roleID, permID string) error {
	return s.assignPermErr
}
func (s *stubRbacHandlerService) RevokePermission(ctx context.Context, roleID, permID string) error {
	return s.revokePermErr
}
func (s *stubRbacHandlerService) InvalidateAll(ctx context.Context) {
	s.invalidateCalled = true
}

func TestRbacHandlerRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubRbacHandlerService{
		listRolesResult: []*entity.Role{{ID: "r1", Name: "admin"}},
		getRoleResult:   &entity.RoleWithPermissions{Role: &entity.Role{ID: "r1", Name: "admin"}},
	}
	h := handler.NewRbacHandler(svc)

	t.Run("list roles", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodGet, "/admin/rbac/roles", nil)
		c.Request = req
		h.ListRoles(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("create role", func(t *testing.T) {
		reqBody := reqdto.CreateRoleRequest{Name: "new-role", Level: 1}
		body, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodPost, "/admin/rbac/roles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req
		h.CreateRole(c)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", w.Code)
		}
	})

	t.Run("error mapping - conflict", func(t *testing.T) {
		svc.createRoleErr = errorx.ErrRoleAlreadyExists
		reqBody := reqdto.CreateRoleRequest{Name: "admin", Level: 1}
		body, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodPost, "/admin/rbac/roles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req
		h.CreateRole(c)
		if w.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d", w.Code)
		}
	})
}

func TestRbacHandlerPermissions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubRbacHandlerService{
		listPermissionsResult: []*entity.Permission{{ID: "p1", Name: "read"}},
	}
	h := handler.NewRbacHandler(svc)

	t.Run("list permissions", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodGet, "/admin/rbac/permissions", nil)
		c.Request = req
		h.ListPermissions(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("assign permission", func(t *testing.T) {
		reqBody := reqdto.AssignPermissionRequest{PermissionID: "p1"}
		body, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodPost, "/admin/rbac/roles/r1/permissions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req
		c.Params = append(c.Params, gin.Param{Key: "id", Value: "r1"})
		h.AssignPermission(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

func TestRbacHandlerCache(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubRbacHandlerService{}
	h := handler.NewRbacHandler(svc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/admin/rbac/cache/invalidate", nil)
	c.Request = req
	h.InvalidateAll(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !svc.invalidateCalled {
		t.Fatalf("expected invalidate service to be called")
	}
}
