package entities

import (
	"github.com/google/uuid"
	"time"
)

// TokenType represents token type
type TokenType string

const (
	TokenTypeAccess        TokenType = "access"
	TokenTypeRefresh       TokenType = "refresh"
	TokenTypePasswordReset TokenType = "password_reset"
	TokenTypeEmailVerify   TokenType = "email_verify"
	TokenTypePhoneVerify   TokenType = "phone_verify"
	TokenTypeMFAChallenge  TokenType = "mfa_challenge"
)

// Token represents token entity
type Token struct {
	ID        uuid.UUID              `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID    uuid.UUID              `json:"user_id" gorm:"type:uuid;not null;index"`
	TokenHash string                 `json:"-" gorm:"not null;uniqueIndex"`
	Type      TokenType              `json:"type" gorm:"not null"`
	ExpiresAt time.Time              `json:"expires_at" gorm:"not null;index"`
	IsRevoked bool                   `json:"is_revoked" gorm:"default:false;index"`
	DeviceID  *string                `json:"device_id"`
	UserAgent *string                `json:"user_agent"`
	IPAddress *string                `json:"ip_address"`
	Metadata  map[string]interface{} `json:"metadata" gorm:"type:jsonb"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`

	// Relations
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// TableName returns table name
func (Token) TableName() string {
	return "tokens"
}

// IsValid checks if token is valid
func (t *Token) IsValid() bool {
	return !t.IsRevoked && t.ExpiresAt.After(time.Now())
}

// IsExpired checks if token is expired
func (t *Token) IsExpired() bool {
	return t.ExpiresAt.Before(time.Now())
}

// Revoke revokes the token
func (t *Token) Revoke() {
	t.IsRevoked = true
	t.UpdatedAt = time.Now()
}

// TokenPair represents access and refresh token pair
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	IssuedAt     time.Time `json:"issued_at"`
}

// JWTClaims represents JWT claims
type JWTClaims struct {
	UserID    uuid.UUID  `json:"user_id"`
	Username  string     `json:"username"`
	Email     string     `json:"email"`
	Role      string     `json:"role"`
	GroupID   *uuid.UUID `json:"group_id,omitempty"`
	TokenID   uuid.UUID  `json:"token_id"`
	TokenType TokenType  `json:"token_type"`
	IssuedAt  int64      `json:"iat"`
	ExpiresAt int64      `json:"exp"`
	NotBefore int64      `json:"nbf"`
	Issuer    string     `json:"iss"`
	Audience  string     `json:"aud"`
}
