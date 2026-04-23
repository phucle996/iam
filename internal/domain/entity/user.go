package entity

import "time"

// User represents the core IAM identity.
type User struct {
	ID            string
	Username      string
	Email         string
	Phone         string
	PasswordHash  string
	SecurityLevel int16
	Status        string
	StatusReason  string
	Role          string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
