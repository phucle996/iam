package model

import "time"

// WhoAmIRow mirrors the joined whoami read model.
type WhoAmIRow struct {
	UserID           string    `db:"user_id"`
	Username         string    `db:"username"`
	Email            string    `db:"email"`
	Phone            string    `db:"phone"`
	SecurityLevel    int16     `db:"security_level"`
	Status           string    `db:"status"`
	StatusReason     string    `db:"status_reason"`
	UserCreatedAt    time.Time `db:"user_created_at"`
	UserUpdatedAt    time.Time `db:"user_updated_at"`
	ProfileID        string    `db:"profile_id"`
	Fullname         string    `db:"fullname"`
	AvatarURL        string    `db:"avatar_url"`
	Bio              string    `db:"bio"`
	Timezone         string    `db:"timezone"`
	ProfileCreatedAt time.Time `db:"profile_created_at"`
	ProfileUpdatedAt time.Time `db:"profile_updated_at"`
	RoleName         string    `db:"role_name"`
	PermissionName   string    `db:"permission_name"`
}
