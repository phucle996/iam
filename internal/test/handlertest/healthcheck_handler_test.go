package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"controlplane/internal/transport/http/handler"
	"github.com/gin-gonic/gin"
)

func TestHealthHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := handler.NewHealthHandler(nil, nil)

	t.Run("liveness", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		h.Liveness(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("startup - not ready", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		h.Startup(c)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", w.Code)
		}
	})

	t.Run("startup - ready", func(t *testing.T) {
		h.MarkReady()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		h.Startup(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("readiness - ready no deps", func(t *testing.T) {
		h.MarkReady()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
		c.Request = req
		h.Readiness(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("readiness - not ready", func(t *testing.T) {
		h.MarkNotReady()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		h.Readiness(c)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", w.Code)
		}
	})
}
