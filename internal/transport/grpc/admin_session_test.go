package grpc

import (
	"context"
	"errors"
	"net"
	"testing"

	"iam/internal/domain/entity"
	"iam/internal/transport/grpc/adminsessionpb"
	"iam/pkg/errorx"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type fakeAdminAuthService struct {
	input entity.AdminSessionAuthInput
	out   *entity.AdminSessionContext
	err   error
}

func (f *fakeAdminAuthService) EnsureBootstrapCredential(ctx context.Context) (*entity.AdminBootstrapResult, error) {
	return nil, nil
}
func (f *fakeAdminAuthService) Login(ctx context.Context, input entity.AdminLoginInput) (*entity.AdminLoginResult, error) {
	return nil, nil
}
func (f *fakeAdminAuthService) AuthorizeSession(ctx context.Context, input entity.AdminSessionAuthInput) (*entity.AdminSessionContext, error) {
	f.input = input
	return f.out, f.err
}
func (f *fakeAdminAuthService) Logout(ctx context.Context, sessionToken string) error { return nil }

func TestAdminSessionServiceAuthorizeSessionMapsContext(t *testing.T) {
	svc := &fakeAdminAuthService{out: &entity.AdminSessionContext{AdminUserID: "admin-1", DisplayName: "Root", CredentialID: "cred-1", DeviceID: "dev-1", SessionID: "sess-1"}}
	client, stop := startAdminSessionTestServer(t, svc)
	defer stop()

	resp, err := client.AuthorizeSession(context.Background(), &adminsessionpb.AuthorizeAdminSessionRequest{SessionToken: "session-token", DeviceId: "dev-1", DeviceSecret: "device-secret", ClientIp: "127.0.0.1", UserAgent: "test-agent"})
	if err != nil {
		t.Fatalf("authorize session: %v", err)
	}
	if resp.GetAdminUserId() != "admin-1" || resp.GetSessionId() != "sess-1" || resp.GetDeviceId() != "dev-1" {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if svc.input.SessionToken != "session-token" || svc.input.DeviceSecret != "device-secret" || svc.input.ClientIP != "127.0.0.1" || svc.input.UserAgent != "test-agent" {
		t.Fatalf("unexpected input: %#v", svc.input)
	}
}

func TestAdminSessionServiceAuthorizeSessionRejectsInvalidSession(t *testing.T) {
	client, stop := startAdminSessionTestServer(t, &fakeAdminAuthService{err: errorx.ErrAdminSessionInvalid})
	defer stop()

	_, err := client.AuthorizeSession(context.Background(), &adminsessionpb.AuthorizeAdminSessionRequest{SessionToken: "bad", DeviceId: "dev", DeviceSecret: "secret"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
}

func TestAdminSessionServiceAuthorizeSessionUnavailableOnCanceled(t *testing.T) {
	client, stop := startAdminSessionTestServer(t, &fakeAdminAuthService{err: context.Canceled})
	defer stop()

	_, err := client.AuthorizeSession(context.Background(), &adminsessionpb.AuthorizeAdminSessionRequest{SessionToken: "token", DeviceId: "dev", DeviceSecret: "secret"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected unavailable, got %v", err)
	}
}

func startAdminSessionTestServer(t *testing.T, svc *fakeAdminAuthService) (adminsessionpb.AdminSessionServiceClient, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := ggrpc.NewServer()
	RegisterAdminSessionService(server, svc)
	go func() {
		if serveErr := server.Serve(lis); serveErr != nil && !errors.Is(serveErr, ggrpc.ErrServerStopped) {
			t.Errorf("serve: %v", serveErr)
		}
	}()
	conn, err := ggrpc.NewClient(lis.Addr().String(), ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return adminsessionpb.NewAdminSessionServiceClient(conn), func() { conn.Close(); server.Stop(); lis.Close() }
}
