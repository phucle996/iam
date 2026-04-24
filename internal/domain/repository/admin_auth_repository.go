package domainrepo

import (
	"context"
	"time"

	"iam/internal/domain/entity"
)

type AdminAuthRepository interface {
	HasAdminCredentials(ctx context.Context) (bool, error)
	CreateBootstrapAdmin(ctx context.Context, admin *entity.AdminUser, credential *entity.AdminAPICredential, mfaMethods []*entity.AdminMFAMethod) error
	GetCredentialByHash(ctx context.Context, tokenHash string, now time.Time) (*entity.AdminAPICredential, *entity.AdminUser, error)
	ListMFAMethods(ctx context.Context, adminUserID string) ([]*entity.AdminMFAMethod, error)
	GetDeviceByID(ctx context.Context, deviceID string) (*entity.AdminDevice, error)
	CreateDevice(ctx context.Context, device *entity.AdminDevice) error
	TrustDevice(ctx context.Context, deviceID string, trustedUntil time.Time) error
	TouchDevice(ctx context.Context, deviceID, ip string, seenAt time.Time) error
	MarkDeviceSuspicious(ctx context.Context, deviceID string) error
	CreateSession(ctx context.Context, session *entity.AdminSession) error
	GetSessionByHash(ctx context.Context, sessionHash string, now time.Time) (*entity.AdminSession, *entity.AdminUser, *entity.AdminAPICredential, *entity.AdminDevice, error)
	RevokeSession(ctx context.Context, sessionHash string, revokedAt time.Time) error
	InsertAudit(ctx context.Context, audit *entity.AuditLog) error
}
