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

// userRepository implements UserRepository interface
type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates new user repository
func NewUserRepository(db *gorm.DB) output.UserRepository {
	return &userRepository{db: db}
}

// Create creates new user
func (r *userRepository) Create(ctx context.Context, user *entities.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return err
	}
	return nil
}

// GetByID gets user by ID
func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*entities.User, error) {
	var user entities.User
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// GetByUsername gets user by username
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*entities.User, error) {
	var user entities.User
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// GetByEmail gets user by email
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	var user entities.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// GetByPhone gets user by phone
func (r *userRepository) GetByPhone(ctx context.Context, phone string) (*entities.User, error) {
	var user entities.User
	if err := r.db.WithContext(ctx).Where("phone = ?", phone).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// GetByIdentifier gets user by username, email, phone or id
func (r *userRepository) GetByIdentifier(ctx context.Context, identifier string) (*entities.User, error) {
	var user entities.User

	// Try to parse as UUID first
	if id, err := uuid.Parse(identifier); err == nil {
		if err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err == nil {
			return &user, nil
		}
	}

	// Try username, email, or phone
	query := r.db.WithContext(ctx).Where(
		"username = ? OR email = ? OR phone = ?",
		identifier, identifier, identifier,
	)

	if err := query.First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// Update updates user
func (r *userRepository) Update(ctx context.Context, user *entities.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

// Delete hard deletes user
func (r *userRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Unscoped().Delete(&entities.User{}, id).Error
}

// SoftDelete soft deletes user
func (r *userRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&entities.User{}, id).Error
}

// UpdateStatus updates user status
func (r *userRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status entities.UserStatus) error {
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Update("status", status).Error
}

// UpdateVerificationStatus updates verification status
func (r *userRepository) UpdateVerificationStatus(ctx context.Context, id uuid.UUID, status entities.VerificationStatus) error {
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Update("verification_status", status).Error
}

// UpdateUserParams updates user role and group
func (r *userRepository) UpdateUserParams(ctx context.Context, id uuid.UUID, roleID, groupID *uuid.UUID) error {
	updates := make(map[string]interface{})

	if roleID != nil {
		updates["role_id"] = *roleID
	}

	if groupID != nil {
		updates["group_id"] = *groupID
	}

	if len(updates) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Updates(updates).Error
}

// UpdatePassword updates user password
func (r *userRepository) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Update("password_hash", passwordHash).Error
}

// UpdateLoginAttempts updates login attempts and locked until
func (r *userRepository) UpdateLoginAttempts(ctx context.Context, id uuid.UUID, attempts int, lockedUntil *time.Time) error {
	updates := map[string]interface{}{
		"login_attempts": attempts,
		"locked_until":   lockedUntil,
	}
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Updates(updates).Error
}

// UpdateLastLogin updates last login info
func (r *userRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID, loginAt time.Time, ip string) error {
	updates := map[string]interface{}{
		"last_login_at": loginAt,
		"last_login_ip": ip,
	}
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Updates(updates).Error
}

// EnableTwoFactor enables two-factor authentication
func (r *userRepository) EnableTwoFactor(ctx context.Context, id uuid.UUID, secret string) error {
	updates := map[string]interface{}{
		"two_factor_enabled": true,
		"two_factor_secret":  secret,
	}
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Updates(updates).Error
}

// DisableTwoFactor disables two-factor authentication
func (r *userRepository) DisableTwoFactor(ctx context.Context, id uuid.UUID) error {
	updates := map[string]interface{}{
		"two_factor_enabled": false,
		"two_factor_secret":  nil,
	}
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Updates(updates).Error
}

// MarkEmailVerified marks email as verified
func (r *userRepository) MarkEmailVerified(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Update("email_verified", true).Error
}

// MarkPhoneVerified marks phone as verified
func (r *userRepository) MarkPhoneVerified(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Update("phone_verified", true).Error
}

// List gets users with pagination
func (r *userRepository) List(ctx context.Context, offset, limit int) ([]*entities.User, error) {
	var users []*entities.User
	if err := r.db.WithContext(ctx).Offset(offset).Limit(limit).Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

// Count gets total user count
func (r *userRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&entities.User{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// ExistsByUsername checks if username exists
func (r *userRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&entities.User{}).Where("username = ?", username).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// ExistsByEmail checks if email exists
func (r *userRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&entities.User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// ExistsByPhone checks if phone exists
func (r *userRepository) ExistsByPhone(ctx context.Context, phone string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&entities.User{}).Where("phone = ?", phone).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
