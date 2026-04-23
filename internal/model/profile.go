package model

import (
	"controlplane/internal/domain/entity"
	"time"
)

// UserProfile mirrors user_profiles.
type UserProfile struct {
	ID        string    `db:"id"`
	UserID    string    `db:"user_id"`
	Fullname  string    `db:"fullname"`
	Bio       *string   `db:"bio"`
	AvatarURL *string   `db:"avatar_url"`
	Timezone  string    `db:"timezone"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func UserProfileEntityToModel(v *entity.UserProfile) *UserProfile {
	if v == nil {
		return nil
	}
	return &UserProfile{
		ID:        v.ID,
		UserID:    v.UserID,
		Fullname:  v.Fullname,
		Bio:       &v.Bio,
		AvatarURL: &v.AvatarURL,
		Timezone:  v.Timezone,
		CreatedAt: v.CreatedAt,
		UpdatedAt: v.UpdatedAt,
	}
}

func UserProfileModelToEntity(v *UserProfile) *entity.UserProfile {
	if v == nil {
		return nil
	}
	return &entity.UserProfile{
		ID:        v.ID,
		UserID:    v.UserID,
		Bio:       *v.Bio,
		Fullname:  v.Fullname,
		AvatarURL: *v.AvatarURL,
		Timezone:  v.Timezone,
		CreatedAt: v.CreatedAt,
		UpdatedAt: v.UpdatedAt,
	}
}

// PasswordHistory mirrors password_histories.
type PasswordHistory struct {
	ID           string    `db:"id"`
	UserID       string    `db:"user_id"`
	PasswordHash string    `db:"password_hash"`
	CreatedAt    time.Time `db:"created_at"`
}

func PasswordHistoryEntityToModel(v *entity.PasswordHistory) *PasswordHistory {
	if v == nil {
		return nil
	}
	return &PasswordHistory{
		ID:           v.ID,
		UserID:       v.UserID,
		PasswordHash: v.PasswordHash,
		CreatedAt:    v.CreatedAt,
	}
}

func PasswordHistoryModelToEntity(v *PasswordHistory) *entity.PasswordHistory {
	if v == nil {
		return nil
	}
	return &entity.PasswordHistory{
		ID:           v.ID,
		UserID:       v.UserID,
		PasswordHash: v.PasswordHash,
		CreatedAt:    v.CreatedAt,
	}
}
