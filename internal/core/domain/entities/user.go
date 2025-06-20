package entities

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

// UserStatus represents user status
type UserStatus int16

const (
	UserStatusActive   UserStatus = 1
	UserStatusBlocked  UserStatus = 2
	UserStatusBanned   UserStatus = 3
	UserStatusLimited  UserStatus = 4
	UserStatusInactive UserStatus = 5
)

// VerificationStatus represents user verification status
type VerificationStatus int16

const (
	VerificationStatusPending  VerificationStatus = 0
	VerificationStatusVerified VerificationStatus = 1
	VerificationStatusRejected VerificationStatus = 2
)

// User represents user entity
type User struct {
	ID                 uuid.UUID              `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Username           string                 `json:"username" gorm:"uniqueIndex;not null"`
	Email              string                 `json:"email" gorm:"uniqueIndex;not null"`
	Phone              *string                `json:"phone,omitempty" gorm:"uniqueIndex"`
	PasswordHash       string                 `json:"-" gorm:"not null"`
	FirstName          string                 `json:"first_name"`
	LastName           string                 `json:"last_name"`
	Role               string                 `json:"role" gorm:"type:varchar(50);default:'user';not null"` // Changed from UserRole to string
	GroupID            *uuid.UUID             `json:"group_id,omitempty" gorm:"type:uuid"`
	Status             UserStatus             `json:"status" gorm:"default:1"`
	VerificationStatus VerificationStatus     `json:"verification_status" gorm:"default:0"`
	EmailVerified      bool                   `json:"email_verified" gorm:"default:false"`
	PhoneVerified      bool                   `json:"phone_verified" gorm:"default:false"`
	TwoFactorEnabled   bool                   `json:"two_factor_enabled" gorm:"default:false"`
	TwoFactorSecret    *string                `json:"-"`
	LastLoginAt        *time.Time             `json:"last_login_at"`
	LastLoginIP        *string                `json:"last_login_ip"`
	LoginAttempts      int                    `json:"login_attempts" gorm:"default:0"`
	LockedUntil        *time.Time             `json:"locked_until"`
	Avatar             *string                `json:"avatar"`
	Metadata           map[string]interface{} `json:"metadata" gorm:"type:jsonb"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
	DeletedAt          gorm.DeletedAt         `json:"deleted_at" gorm:"index"`
}

// TableName returns table name
func (User) TableName() string {
	return "users"
}

// IsActive checks if user is active
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

// IsBlocked checks if user is blocked
func (u *User) IsBlocked() bool {
	return u.Status == UserStatusBlocked
}

// IsBanned checks if user is banned
func (u *User) IsBanned() bool {
	return u.Status == UserStatusBanned
}

// IsLimited checks if user is limited
func (u *User) IsLimited() bool {
	return u.Status == UserStatusLimited
}

// IsLocked checks if user account is temporarily locked
func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

// CanLogin checks if user can login
func (u *User) CanLogin() bool {
	return u.IsActive() && !u.IsLocked() && u.DeletedAt.Time.IsZero()
}

// GetFullName returns user's full name
func (u *User) GetFullName() string {
	if u.FirstName == "" && u.LastName == "" {
		return u.Username
	}
	return u.FirstName + " " + u.LastName
}

// IncrementLoginAttempts increments login attempts
func (u *User) IncrementLoginAttempts() {
	u.LoginAttempts++
	if u.LoginAttempts >= 5 {
		u.LockedUntil = &time.Time{}
		*u.LockedUntil = time.Now().Add(30 * time.Minute)
	}
}

// ResetLoginAttempts resets login attempts
func (u *User) ResetLoginAttempts() {
	u.LoginAttempts = 0
	u.LockedUntil = nil
}

// UpdateLastLogin updates last login info
func (u *User) UpdateLastLogin(ip string) {
	now := time.Now()
	u.LastLoginAt = &now
	u.LastLoginIP = &ip
}
