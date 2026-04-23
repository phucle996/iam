package model

import (
	"time"

	"controlplane/internal/domain/entity"
)

// User represents the database schema map for IAM users.
type User struct {
	ID            string    `db:"id"`
	Username      string    `db:"username"`
	Email         string    `db:"email"`
	Phone         *string   `db:"phone"`
	PasswordHash  string    `db:"password_hash"`
	SecurityLevel int16     `db:"security_level"`
	Status        string    `db:"status"`
	StatusReason  *string   `db:"status_reason"`
	Role          *string   `db:"role"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}

func UserEntityToModel(u *entity.User) *User {
	if u == nil {
		return nil
	}

	return &User{
		ID:            u.ID,
		Username:      u.Username,
		Email:         u.Email,
		Phone:         &u.Phone,
		PasswordHash:  u.PasswordHash,
		SecurityLevel: u.SecurityLevel,
		Status:        u.Status,
		StatusReason:  &u.StatusReason,
		Role:          &u.Role,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

func UserModelToEntity(m *User) *entity.User {
	if m == nil {
		return nil
	}

	return &entity.User{
		ID:            m.ID,
		Username:      m.Username,
		Email:         m.Email,
		Phone:         *m.Phone,
		PasswordHash:  m.PasswordHash,
		SecurityLevel: m.SecurityLevel,
		Status:        m.Status,
		StatusReason:  *m.StatusReason,
		Role:          *m.Role,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}
