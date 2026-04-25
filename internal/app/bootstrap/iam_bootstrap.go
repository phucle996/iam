package bootstrap

import (
	"context"
	"fmt"
	"time"

	"iam/infra/telegram"
	domainsvc "iam/internal/domain/service"
	"iam/internal/repository"
	"iam/internal/security"
	"iam/pkg/logger"
)

// EnsureInitialSecrets seeds the database with initial system secrets if they don't exist.
func EnsureInitialSecrets(ctx context.Context, repo *repository.SecretRepository, masterKey string) error {
	if repo == nil {
		return nil
	}

	for _, family := range security.SecretFamilies() {
		exists, err := repo.HasAny(ctx, family)
		if err != nil {
			return err
		}
		if exists {
			continue
		}

		plain, err := security.GenerateToken(128, masterKey)
		if err != nil {
			return err
		}

		cipher, err := security.EncryptSecret(plain, masterKey)
		if err != nil {
			return err
		}

		err = repo.CreateSecretVersion(ctx, security.SecretVersion{
			Family:    family,
			Version:   1,
			Value:     cipher,
			ExpiresAt: time.Now().AddDate(10, 0, 0),
			RotatedAt: time.Now(),
		})
		if err != nil {
			return err
		}
		logger.SysInfo("bootstrap", fmt.Sprintf("iam: seeded initial secret family %s", family))
	}

	return nil
}

func EnsureAdminBootstrapToken(ctx context.Context, adminSvc domainsvc.AdminAPITokenService, tele *telegram.TelegramClient) error {
	if adminSvc == nil {
		return nil
	}

	token, created, err := adminSvc.EnsureBootstrapToken(ctx)
	if err != nil {
		return err
	}

	if !created {
		return nil
	}

	logger.SysInfo("bootstrap", "iam: bootstrap admin credential created")

	if tele != nil {
		msg := fmt.Sprintf("<b>Aurora IAM Bootstrap</b>\n\nAdmin API Token: <code>%s</code>\n\n<i>This token is only sent once. Make sure to save it safely.</i>", token)
		if err := tele.SendMessage(msg); err != nil {
			logger.SysWarn("bootstrap", fmt.Sprintf("iam: failed to send bootstrap token to telegram: %v", err))
		} else {
			logger.SysInfo("bootstrap", "iam: bootstrap token sent to telegram")
		}
	} else {
		logger.SysWarn("bootstrap", "iam: bootstrap admin credential created but telegram is not configured. The token cannot be recovered!")
	}

	return nil
}

// EnsureAdminAuthBootstrap ensures a system admin user exists with 2FA enabled.
func EnsureAdminAuthBootstrap(ctx context.Context, authSvc domainsvc.AdminAuthService, tele *telegram.TelegramClient) error {
	if authSvc == nil {
		return nil
	}

	res, err := authSvc.EnsureBootstrapCredential(ctx)
	if err != nil {
		return err
	}

	if !res.Created {
		return nil
	}

	logger.SysInfo("bootstrap", "iam: bootstrap admin user created with 2FA")

	if tele != nil {
		codes := ""
		for i, code := range res.RecoveryCodes {
			codes += fmt.Sprintf("%d. <code>%s</code>\n", i+1, code)
		}

		msg := fmt.Sprintf("🔐 <b>Aurora IAM: Admin Bootstrap</b>\n\n"+
			"🔑 <b>Login Key:</b> <code>%s</code>\n\n"+
			"🛡️ <b>2FA TOTP Secret:</b> <code>%s</code>\n"+
			"<i>(Scan this secret into your Authenticator app)</i>\n\n"+
			"⚠️ <b>Recovery Codes:</b>\n%s\n"+
			"<i>Keep these codes safe! They are only sent once.</i>",
			res.AdminKey, res.TOTPSecret, codes)

		if err := tele.SendMessage(msg); err != nil {
			logger.SysWarn("bootstrap", fmt.Sprintf("iam: failed to send bootstrap admin auth to telegram: %v", err))
		} else {
			logger.SysInfo("bootstrap", "iam: bootstrap admin auth sent to telegram")
		}
	} else {
		logger.SysWarn("bootstrap", "iam: bootstrap admin user created but telegram is not configured. Security credentials cannot be recovered!")
	}

	return nil
}
