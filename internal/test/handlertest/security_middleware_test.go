package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"controlplane/internal/domain/entity"
	"controlplane/internal/transport/http/middleware"

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

func TestAdminAPITokenMiddlewareSetsRotatedCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/admin/test", middleware.AdminAPIToken(func(ctx context.Context, token string) (*entity.AdminAPIAuthorization, error) {
		if token != "old-token" {
			return &entity.AdminAPIAuthorization{Valid: false}, nil
		}
		return &entity.AdminAPIAuthorization{
			Valid:       true,
			CookieToken: "new-token",
			ExpiresAt:   time.Now().UTC().Add(10 * time.Minute),
		}, nil
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

	resp := w.Result()
	defer resp.Body.Close()
	found := false
	for _, ck := range resp.Cookies() {
		if ck.Name == "apitoken" {
			found = true
			if ck.Path != "/admin" {
				t.Fatalf("expected /admin cookie path, got %q", ck.Path)
			}
		}
	}
	if !found {
		t.Fatalf("expected rotated apitoken cookie")
	}
}
