package grpc

import (
	"context"
	"errors"

	"iam/internal/domain/entity"
	domainservice "iam/internal/domain/service"
	"iam/internal/transport/grpc/adminsessionpb"
	"iam/pkg/errorx"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type adminSessionServer struct {
	adminsessionpb.UnimplementedAdminSessionServiceServer
	svc domainservice.AdminAuthService
}

func RegisterAdminSessionService(server grpc.ServiceRegistrar, svc domainservice.AdminAuthService) {
	if server == nil || svc == nil {
		return
	}
	adminsessionpb.RegisterAdminSessionServiceServer(server, &adminSessionServer{svc: svc})
}

func (s *adminSessionServer) AuthorizeSession(ctx context.Context, req *adminsessionpb.AuthorizeAdminSessionRequest) (*adminsessionpb.AuthorizeAdminSessionResponse, error) {
	if s == nil || s.svc == nil {
		return nil, status.Error(codes.Unavailable, "admin authentication unavailable")
	}
	if req.GetSessionToken() == "" || req.GetDeviceId() == "" || req.GetDeviceSecret() == "" {
		return nil, status.Error(codes.Unauthenticated, "unauthorized")
	}
	authCtx, err := s.svc.AuthorizeSession(ctx, entity.AdminSessionAuthInput{
		SessionToken: req.GetSessionToken(),
		DeviceID:     req.GetDeviceId(),
		DeviceSecret: req.GetDeviceSecret(),
		ClientIP:     req.GetClientIp(),
		UserAgent:    req.GetUserAgent(),
	})
	if err != nil || authCtx == nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, status.Error(codes.Unavailable, "admin authentication unavailable")
		}
		if errors.Is(err, errorx.ErrAdminDeviceInvalid) {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}
		return nil, status.Error(codes.Unauthenticated, "unauthorized")
	}
	return &adminsessionpb.AuthorizeAdminSessionResponse{
		AdminUserId:  authCtx.AdminUserID,
		DisplayName:  authCtx.DisplayName,
		CredentialId: authCtx.CredentialID,
		DeviceId:     authCtx.DeviceID,
		SessionId:    authCtx.SessionID,
	}, nil
}
