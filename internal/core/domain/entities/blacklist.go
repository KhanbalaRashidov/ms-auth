package entities

import (
	"github.com/google/uuid"
	"time"
)

// BlacklistType represents blacklist type
type BlacklistType string

const (
	BlacklistTypeEmail    BlacklistType = "email"
	BlacklistTypePhone    BlacklistType = "phone"
	BlacklistTypeUsername BlacklistType = "username"
	BlacklistTypeIP       BlacklistType = "ip"
	BlacklistTypeDevice   BlacklistType = "device"
	BlacklistTypeDomain   BlacklistType = "domain"
)

// Blacklist represents blacklist entity
type Blacklist struct {
	ID        uuid.UUID              `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Type      BlacklistType          `json:"type" gorm:"not null;index"`
	Value     string                 `json:"value" gorm:"not null;index"`
	Reason    string                 `json:"reason"`
	IsActive  bool                   `json:"is_active" gorm:"default:true;index"`
	ExpiresAt *time.Time             `json:"expires_at"`
	CreatedBy *uuid.UUID             `json:"created_by" gorm:"type:uuid"`
	Metadata  map[string]interface{} `json:"metadata" gorm:"type:jsonb"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// TableName returns table name
func (Blacklist) TableName() string {
	return "blacklists"
}

// IsValid checks if blacklist entry is valid
func (b *Blacklist) IsValid() bool {
	if !b.IsActive {
		return false
	}

	if b.ExpiresAt != nil && b.ExpiresAt.Before(time.Now()) {
		return false
	}

	return true
}

// IsExpired checks if blacklist entry is expired
func (b *Blacklist) IsExpired() bool {
	return b.ExpiresAt != nil && b.ExpiresAt.Before(time.Now())
}

// Deactivate deactivates blacklist entry
func (b *Blacklist) Deactivate() {
	b.IsActive = false
	b.UpdatedAt = time.Now()
}
