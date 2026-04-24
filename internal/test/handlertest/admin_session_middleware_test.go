package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"iam/internal/domain/entity"
	"iam/internal/transport/http/middleware"
	"iam/pkg/errorx"

	"github.com/gin-gonic/gin"
)

func TestAdminSessionMiddlewareAllowsValidBoundDevice(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/admin/test", middleware.AdminSession(func(ctx context.Context, input entity.AdminSessionAuthInput) (*entity.AdminSessionContext, error) {
		if input.SessionToken != "session-token" || input.DeviceID != "device-1" || input.DeviceSecret != "device-secret" {
			return nil, errorx.ErrAdminSessionInvalid
		}
		return &entity.AdminSessionContext{
			AdminUserID: "admin-1",
			SessionID:   "session-1",
			ExpiresAt:   time.Now().UTC().Add(time.Hour),
		}, nil
	}), func(c *gin.Context) {
		if middleware.GetAdminUserID(c) != "admin-1" {
			t.Fatalf("expected admin context on request")
		}
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-aurora_admin_session", Value: "session-token"})
	req.AddCookie(&http.Cookie{Name: "__Host-aurora_admin_device_id", Value: "device-1"})
	req.AddCookie(&http.Cookie{Name: "__Host-aurora_admin_device_secret", Value: "device-secret"})
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestAdminSessionMiddlewareRejectsMissingDeviceBinding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/admin/test", middleware.AdminSession(func(ctx context.Context, input entity.AdminSessionAuthInput) (*entity.AdminSessionContext, error) {
		t.Fatalf("authorize should not be called without device cookies")
		return nil, nil
	}), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-aurora_admin_session", Value: "session-token"})
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
