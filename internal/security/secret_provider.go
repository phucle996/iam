package security

import (
	"errors"
	"time"
)

const (
	SecretFamilyAccess   = "access"
	SecretFamilyRefresh  = "refresh"
	SecretFamilyOneTime  = "one_time"
	SecretFamilyAdminAPI = "admin_api"
)

var (
	ErrSecretUnavailable = errors.New("security: secret unavailable")
)

type SecretVersion struct {
	Family    string
	Version   int64
	Value     string
	ExpiresAt time.Time
	RotatedAt time.Time
}

type SecretProvider interface {
	GetActive(family string) (SecretVersion, error)
	GetCandidates(family string) ([]SecretVersion, error)
}

func SecretFamilies() []string {
	return []string{
		SecretFamilyAccess,
		SecretFamilyRefresh,
		SecretFamilyOneTime,
		SecretFamilyAdminAPI,
	}
}
