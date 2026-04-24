package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"iam/internal/domain/entity"
	"iam/internal/transport/http/middleware"

	"github.com/gin-gonic/gin"
)

func TestCookieOriginGuardRejectsCookieUnsafeWithoutOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(middleware.CookieOriginGuard([]string{"https://app.example.com"}))
	r.POST("/unsafe", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/unsafe", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "token-1"})
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCookieOriginGuardAllowsCookieUnsafeWithAllowedOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(middleware.CookieOriginGuard([]string{"https://app.example.com"}))
	r.POST("/unsafe", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/unsafe", nil)
	req.Host = "api.example.com"
	req.Header.Set("Origin", "https://app.example.com")
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "token-1"})
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestCookieOriginGuardSkipsBearerRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(middleware.CookieOriginGuard([]string{"https://app.example.com"}))
	r.POST("/unsafe", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/unsafe", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestAdminAPITokenMiddlewareAllowsValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/admin/test", middleware.AdminAPIToken(func(ctx context.Context, token string) (*entity.AdminAPIAuthorization, error) {
		if token != "old-token" {
			return &entity.AdminAPIAuthorization{Valid: false}, nil
		}
		return &entity.AdminAPIAuthorization{Valid: true}, nil
	}), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
	req.AddCookie(&http.Cookie{Name: "apitoken", Value: "old-token"})
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}
