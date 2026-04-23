package entity

import "time"

// UserProfile stores optional profile data for a user.
type UserProfile struct {
	ID        string
	UserID    string
	Bio       string
	Fullname  string
	AvatarURL string
	Timezone  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PasswordHistory stores prior password hashes for reuse prevention.
type PasswordHistory struct {
	ID           string
	UserID       string
	PasswordHash string
	CreatedAt    time.Time
}
