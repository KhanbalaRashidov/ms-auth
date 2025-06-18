package entities

import (
	"github.com/google/uuid"
	"time"
)

// PasswordHistory represents password history entity
type PasswordHistory struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID       uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	PasswordHash string    `json:"-" gorm:"not null"`
	CreatedAt    time.Time `json:"created_at"`

	// Relations
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// TableName returns table name
func (PasswordHistory) TableName() string {
	return "password_histories"
}

// PasswordComplexity represents password complexity requirements
type PasswordComplexity struct {
	MinLength      int  `json:"min_length" validate:"min=6,max=128"`
	MaxLength      int  `json:"max_length" validate:"min=6,max=128"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireDigit   bool `json:"require_digit"`
	RequireSpecial bool `json:"require_special"`
	PreventReuse   int  `json:"prevent_reuse" validate:"min=0,max=24"`
	MaxAge         int  `json:"max_age"` // in days
}

// DefaultPasswordComplexity returns default password complexity
func DefaultPasswordComplexity() PasswordComplexity {
	return PasswordComplexity{
		MinLength:      8,
		MaxLength:      128,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		PreventReuse:   5,
		MaxAge:         90,
	}
}
