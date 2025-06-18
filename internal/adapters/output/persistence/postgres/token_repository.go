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

// tokenRepository implements TokenRepository interface
type tokenRepository struct {
	db *gorm.DB
}

// NewTokenRepository creates new token repository
func NewTokenRepository(db *gorm.DB) output.TokenRepository {
	return &tokenRepository{db: db}
}

// Create creates new token
func (r *tokenRepository) Create(ctx context.Context, token *entities.Token) error {
	return r.db.WithContext(ctx).Create(token).Error
}

// GetByID gets token by ID
func (r *tokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*entities.Token, error) {
	var token entities.Token
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("token not found")
		}
		return nil, err
	}
	return &token, nil
}

// GetByHash gets token by hash
func (r *tokenRepository) GetByHash(ctx context.Context, tokenHash string) (*entities.Token, error) {
	var token entities.Token
	if err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("token not found")
		}
		return nil, err
	}
	return &token, nil
}

// Update updates token
func (r *tokenRepository) Update(ctx context.Context, token *entities.Token) error {
	return r.db.WithContext(ctx).Save(token).Error
}

// Delete deletes token
func (r *tokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&entities.Token{}, id).Error
}

// RevokeToken revokes specific token
func (r *tokenRepository) RevokeToken(ctx context.Context, id uuid.UUID) error {
	updates := map[string]interface{}{
		"is_revoked": true,
		"updated_at": time.Now(),
	}
	return r.db.WithContext(ctx).Model(&entities.Token{}).Where("id = ?", id).Updates(updates).Error
}

// RevokeAllUserTokens revokes all user tokens of specific type
func (r *tokenRepository) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) error {
	updates := map[string]interface{}{
		"is_revoked": true,
		"updated_at": time.Now(),
	}
	return r.db.WithContext(ctx).Model(&entities.Token{}).
		Where("user_id = ? AND type = ? AND is_revoked = false", userID, tokenType).
		Updates(updates).Error
}

// RevokeAllUserTokensExcept revokes all user tokens except specified one
func (r *tokenRepository) RevokeAllUserTokensExcept(ctx context.Context, userID uuid.UUID, exceptTokenID uuid.UUID) error {
	updates := map[string]interface{}{
		"is_revoked": true,
		"updated_at": time.Now(),
	}
	return r.db.WithContext(ctx).Model(&entities.Token{}).
		Where("user_id = ? AND id != ? AND is_revoked = false", userID, exceptTokenID).
		Updates(updates).Error
}

// GetUserTokens gets user tokens of specific type
func (r *tokenRepository) GetUserTokens(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) ([]*entities.Token, error) {
	var tokens []*entities.Token
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND type = ?", userID, tokenType).
		Order("created_at DESC").
		Find(&tokens).Error; err != nil {
		return nil, err
	}
	return tokens, nil
}

// GetValidToken gets valid token by hash and type
func (r *tokenRepository) GetValidToken(ctx context.Context, tokenHash string, tokenType entities.TokenType) (*entities.Token, error) {
	var token entities.Token
	if err := r.db.WithContext(ctx).
		Where("token_hash = ? AND type = ? AND is_revoked = false AND expires_at > ?",
			tokenHash, tokenType, time.Now()).
		First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("token not found or expired")
		}
		return nil, err
	}
	return &token, nil
}

// CleanupExpiredTokens removes expired tokens
func (r *tokenRepository) CleanupExpiredTokens(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&entities.Token{}).Error
}

// GetUserSessions gets user active sessions (refresh tokens)
func (r *tokenRepository) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*entities.Token, error) {
	var tokens []*entities.Token
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND type = ? AND is_revoked = false AND expires_at > ?",
			userID, entities.TokenTypeRefresh, time.Now()).
		Order("created_at DESC").
		Find(&tokens).Error; err != nil {
		return nil, err
	}
	return tokens, nil
}

// RevokeDeviceTokens revokes all tokens for specific device
func (r *tokenRepository) RevokeDeviceTokens(ctx context.Context, userID uuid.UUID, deviceID string) error {
	updates := map[string]interface{}{
		"is_revoked": true,
		"updated_at": time.Now(),
	}
	return r.db.WithContext(ctx).Model(&entities.Token{}).
		Where("user_id = ? AND device_id = ? AND is_revoked = false", userID, deviceID).
		Updates(updates).Error
}
