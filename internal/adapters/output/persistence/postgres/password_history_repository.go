package postgres

import (
	"context"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"ms-auth/internal/core/domain/entities"
	"ms-auth/internal/core/ports/output"
	"time"
)

// passwordHistoryRepository implements PasswordHistoryRepository interface
type passwordHistoryRepository struct {
	db *gorm.DB
}

// NewPasswordHistoryRepository creates new password history repository
func NewPasswordHistoryRepository(db *gorm.DB) output.PasswordHistoryRepository {
	return &passwordHistoryRepository{db: db}
}

// Create creates new password history entry
func (r *passwordHistoryRepository) Create(ctx context.Context, history *entities.PasswordHistory) error {
	return r.db.WithContext(ctx).Create(history).Error
}

// GetUserPasswordHistory gets user's password history
func (r *passwordHistoryRepository) GetUserPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]*entities.PasswordHistory, error) {
	var histories []*entities.PasswordHistory
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&histories).Error; err != nil {
		return nil, err
	}
	return histories, nil
}

// IsPasswordReused checks if password has been used recently
func (r *passwordHistoryRepository) IsPasswordReused(ctx context.Context, userID uuid.UUID, passwordHash string, checkCount int) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&entities.PasswordHistory{}).
		Where("user_id = ? AND password_hash = ?", userID, passwordHash).
		Order("created_at DESC").
		Limit(checkCount).
		Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}

// CleanupOldPasswords keeps only the specified number of recent passwords
func (r *passwordHistoryRepository) CleanupOldPasswords(ctx context.Context, userID uuid.UUID, keepCount int) error {
	// Get IDs of passwords to keep
	var keepIDs []uuid.UUID
	if err := r.db.WithContext(ctx).Model(&entities.PasswordHistory{}).
		Select("id").
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(keepCount).
		Pluck("id", &keepIDs).Error; err != nil {
		return err
	}

	if len(keepIDs) == 0 {
		return nil
	}

	// Delete passwords not in the keep list
	return r.db.WithContext(ctx).
		Where("user_id = ? AND id NOT IN ?", userID, keepIDs).
		Delete(&entities.PasswordHistory{}).Error
}

// CleanupExpiredPasswords removes passwords older than maxAge
func (r *passwordHistoryRepository) CleanupExpiredPasswords(ctx context.Context, maxAge time.Duration) error {
	cutoffTime := time.Now().Add(-maxAge)
	return r.db.WithContext(ctx).
		Where("created_at < ?", cutoffTime).
		Delete(&entities.PasswordHistory{}).Error
}
