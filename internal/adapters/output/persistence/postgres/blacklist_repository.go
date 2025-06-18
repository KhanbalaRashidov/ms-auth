package postgres

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"ms-auth/internal/core/domain/entities"
	"ms-auth/internal/core/ports/output"
	"time"
)

// blacklistRepository implements BlacklistRepository interface
type blacklistRepository struct {
	db *gorm.DB
}

// NewBlacklistRepository creates new blacklist repository
func NewBlacklistRepository(db *gorm.DB) output.BlacklistRepository {
	return &blacklistRepository{db: db}
}

// Create creates new blacklist entry
func (r *blacklistRepository) Create(ctx context.Context, blacklist *entities.Blacklist) error {
	return r.db.WithContext(ctx).Create(blacklist).Error
}

// GetByID gets blacklist entry by ID
func (r *blacklistRepository) GetByID(ctx context.Context, id uuid.UUID) (*entities.Blacklist, error) {
	var blacklist entities.Blacklist
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&blacklist).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("blacklist entry not found")
		}
		return nil, err
	}
	return &blacklist, nil
}

// Update updates blacklist entry
func (r *blacklistRepository) Update(ctx context.Context, blacklist *entities.Blacklist) error {
	return r.db.WithContext(ctx).Save(blacklist).Error
}

// Delete deletes blacklist entry
func (r *blacklistRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&entities.Blacklist{}, id).Error
}

// IsBlacklisted checks if value is blacklisted
func (r *blacklistRepository) IsBlacklisted(ctx context.Context, blacklistType entities.BlacklistType, value string) (bool, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&entities.Blacklist{}).
		Where("type = ? AND value = ? AND is_active = true", blacklistType, value)

	// Check expiration
	query = query.Where("expires_at IS NULL OR expires_at > ?", time.Now())

	if err := query.Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}

// GetByTypeAndValue gets blacklist entry by type and value
func (r *blacklistRepository) GetByTypeAndValue(ctx context.Context, blacklistType entities.BlacklistType, value string) (*entities.Blacklist, error) {
	var blacklist entities.Blacklist
	if err := r.db.WithContext(ctx).
		Where("type = ? AND value = ?", blacklistType, value).
		First(&blacklist).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("blacklist entry not found")
		}
		return nil, err
	}
	return &blacklist, nil
}

// Deactivate deactivates blacklist entry
func (r *blacklistRepository) Deactivate(ctx context.Context, id uuid.UUID) error {
	updates := map[string]interface{}{
		"is_active":  false,
		"updated_at": time.Now(),
	}
	return r.db.WithContext(ctx).Model(&entities.Blacklist{}).
		Where("id = ?", id).Updates(updates).Error
}

// List gets blacklist entries with pagination
func (r *blacklistRepository) List(ctx context.Context, blacklistType entities.BlacklistType, offset, limit int) ([]*entities.Blacklist, error) {
	var blacklists []*entities.Blacklist
	query := r.db.WithContext(ctx)

	if blacklistType != "" {
		query = query.Where("type = ?", blacklistType)
	}

	if err := query.Offset(offset).Limit(limit).
		Order("created_at DESC").Find(&blacklists).Error; err != nil {
		return nil, err
	}

	return blacklists, nil
}

// CleanupExpired removes expired blacklist entries
func (r *blacklistRepository) CleanupExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).
		Delete(&entities.Blacklist{}).Error
}

// CheckMultiple checks multiple values for blacklisting
func (r *blacklistRepository) CheckMultiple(ctx context.Context, checks []struct {
	Type  entities.BlacklistType
	Value string
}) (map[string]bool, error) {
	result := make(map[string]bool)

	for _, check := range checks {
		key := string(check.Type) + ":" + check.Value
		isBlacklisted, err := r.IsBlacklisted(ctx, check.Type, check.Value)
		if err != nil {
			return nil, err
		}
		result[key] = isBlacklisted
	}

	return result, nil
}
