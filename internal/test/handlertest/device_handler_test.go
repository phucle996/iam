package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"controlplane/internal/domain/entity"
	"controlplane/internal/transport/http/handler"
	"controlplane/internal/transport/http/middleware"
	reqdto "controlplane/internal/transport/http/request"
	"controlplane/pkg/errorx"
	"controlplane/pkg/logger"

	"github.com/gin-gonic/gin"
)

type stubDeviceHandlerService struct {
	challengeResult  *entity.DeviceChallenge
	challengeErr     error
	verifyErr        error
	rotateErr        error
	rebindErr        error
	revokeErr        error
	quarantineErr    error
	listResult       []*entity.Device
	listErr          error
	adminGetResult   *entity.Device
	adminGetErr      error
	adminRevokeErr   error
	markSuspiciousErr error
	cleanupResult    int64
	cleanupErr       error
}

func (s *stubDeviceHandlerService) ResolveDevice(ctx context.Context, userID, fingerprint, publicKey, keyAlgorithm string) (*entity.Device, error) {
	return &entity.Device{}, nil
}
func (s *stubDeviceHandlerService) UpdateActivity(ctx context.Context, deviceID string) error {
	return nil
}
func (s *stubDeviceHandlerService) IssueChallenge(ctx context.Context, userID, deviceID string) (*entity.DeviceChallenge, error) {
	return s.challengeResult, s.challengeErr
}
func (s *stubDeviceHandlerService) VerifyProof(ctx context.Context, proof *entity.DeviceProof) error {
	return s.verifyErr
}
func (s *stubDeviceHandlerService) RotateKey(ctx context.Context, userID, deviceID, newPublicKey, newAlgorithm string) error {
	return s.rotateErr
}
func (s *stubDeviceHandlerService) Rebind(ctx context.Context, userID string, proof *entity.DeviceProof) error {
	return s.rebindErr
}
func (s *stubDeviceHandlerService) Revoke(ctx context.Context, userID, deviceID string) error {
	return s.revokeErr
}
func (s *stubDeviceHandlerService) GetByID(ctx context.Context, userID, deviceID string) (*entity.Device, error) {
	return &entity.Device{}, nil
}
func (s *stubDeviceHandlerService) RevokeOne(ctx context.Context, userID, deviceID string) error {
	return s.revokeErr
}
func (s *stubDeviceHandlerService) RevokeOthers(ctx context.Context, userID, deviceID string) (int64, error) {
	return 1, s.revokeErr
}
func (s *stubDeviceHandlerService) Quarantine(ctx context.Context, deviceID string) error {
	return s.quarantineErr
}
func (s *stubDeviceHandlerService) ListByUserID(ctx context.Context, userID string) ([]*entity.Device, error) {
	return s.listResult, s.listErr
}
func (s *stubDeviceHandlerService) AdminGetByID(ctx context.Context, deviceID string) (*entity.Device, error) {
	return s.adminGetResult, s.adminGetErr
}
func (s *stubDeviceHandlerService) AdminRevoke(ctx context.Context, deviceID string) error {
	return s.adminRevokeErr
}
func (s *stubDeviceHandlerService) MarkSuspicious(ctx context.Context, deviceID string, suspicious bool) error {
	return s.markSuspiciousErr
}
func (s *stubDeviceHandlerService) CleanupStale(ctx context.Context, before time.Time) (int64, error) {
	return s.cleanupResult, s.cleanupErr
}

func TestDeviceHandlerIssueChallenge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubDeviceHandlerService{
		challengeResult: &entity.DeviceChallenge{ChallengeID: "c1", Nonce: "n1", ExpiresAt: time.Now().Add(time.Minute)},
	}
	h := handler.NewDeviceHandler(svc)

	t.Run("success", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodPost, "/devices/challenge", nil)
		c.Request = req
		c.Set(middleware.CtxKeyUserID, "u1")
		c.Set(middleware.CtxKeyDeviceID, "d1")

		h.IssueChallenge(c)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("error mapping - not found", func(t *testing.T) {
		svc.challengeErr = errorx.ErrDeviceNotFound
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodPost, "/devices/challenge", nil)
		c.Request = req
		c.Set(middleware.CtxKeyUserID, "u1")
		c.Set(middleware.CtxKeyDeviceID, "d1")
		h.IssueChallenge(c)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})
}

func TestDeviceHandlerVerifyProof(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubDeviceHandlerService{}
	h := handler.NewDeviceHandler(svc)

	reqBody := reqdto.VerifyProofRequest{ChallengeID: "c1", Signature: "sig"}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/devices/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	c.Set(middleware.CtxKeyDeviceID, "d1")

	h.VerifyProof(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDeviceHandlerListMyDevices(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubDeviceHandlerService{
		listResult: []*entity.Device{{ID: "d1", UserID: "u1"}},
	}
	h := handler.NewDeviceHandler(svc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/me/devices", nil)
	c.Request = req
	c.Set(middleware.CtxKeyUserID, "u1")

	h.ListMyDevices(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"ID":"d1"`)) {
		t.Fatalf("expected device ID in response, got %s", w.Body.String())
	}
}

func TestDeviceHandlerAdminActions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubDeviceHandlerService{
		adminGetResult: &entity.Device{ID: "d1"},
		cleanupResult:  5,
	}
	h := handler.NewDeviceHandler(svc)

	t.Run("admin get", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodGet, "/admin/devices/d1", nil)
		c.Request = req
		c.Params = append(c.Params, gin.Param{Key: "id", Value: "d1"})
		h.AdminGetDevice(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("admin cleanup", func(t *testing.T) {
		reqBody := reqdto.CleanupStaleRequest{InactiveDays: 30}
		body, _ := json.Marshal(reqBody)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodDelete, "/admin/devices/stale", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req
		h.AdminCleanupStale(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if !bytes.Contains(w.Body.Bytes(), []byte(`"removed":5`)) {
			t.Fatalf("expected removed count, got %s", w.Body.String())
		}
	})
}

func TestDeviceHandlerRevokeActions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.InitLogger()
	svc := &stubDeviceHandlerService{}
	h := handler.NewDeviceHandler(svc)

	t.Run("revoke device", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodDelete, "/devices/d1/revoke", nil)
		c.Request = req
		c.Params = append(c.Params, gin.Param{Key: "id", Value: "d1"})
		c.Set(middleware.CtxKeyUserID, "u1")
		h.RevokeDevice(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("revoke others", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req, _ := http.NewRequest(http.MethodDelete, "/me/devices/others", nil)
		c.Request = req
		c.Set(middleware.CtxKeyUserID, "u1")
		c.Set(middleware.CtxKeyDeviceID, "d1")
		h.RevokeOtherDevices(c)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}
