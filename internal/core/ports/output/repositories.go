package output

import (
	"context"
	"github.com/google/uuid"
	"ms-auth/internal/core/domain/entities"
	"time"
)

// UserRepository defines user repository interface
type UserRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, user *entities.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*entities.User, error)
	GetByUsername(ctx context.Context, username string) (*entities.User, error)
	GetByEmail(ctx context.Context, email string) (*entities.User, error)
	GetByPhone(ctx context.Context, phone string) (*entities.User, error)
	GetByIdentifier(ctx context.Context, identifier string) (*entities.User, error) // username, email, phone or id
	Update(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error

	// User status operations
	UpdateStatus(ctx context.Context, id uuid.UUID, status entities.UserStatus) error
	UpdateVerificationStatus(ctx context.Context, id uuid.UUID, status entities.VerificationStatus) error
	UpdateUserParams(ctx context.Context, id uuid.UUID, roleID, groupID *uuid.UUID) error

	// Authentication related
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	UpdateLoginAttempts(ctx context.Context, id uuid.UUID, attempts int, lockedUntil *time.Time) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID, loginAt time.Time, ip string) error

	// Two-factor authentication
	EnableTwoFactor(ctx context.Context, id uuid.UUID, secret string) error
	DisableTwoFactor(ctx context.Context, id uuid.UUID) error

	// Verification
	MarkEmailVerified(ctx context.Context, id uuid.UUID) error
	MarkPhoneVerified(ctx context.Context, id uuid.UUID) error

	// Query operations
	List(ctx context.Context, offset, limit int) ([]*entities.User, error)
	Count(ctx context.Context) (int64, error)
	ExistsByUsername(ctx context.Context, username string) (bool, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	ExistsByPhone(ctx context.Context, phone string) (bool, error)
}

// TokenRepository defines token repository interface
type TokenRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, token *entities.Token) error
	GetByID(ctx context.Context, id uuid.UUID) (*entities.Token, error)
	GetByHash(ctx context.Context, tokenHash string) (*entities.Token, error)
	Update(ctx context.Context, token *entities.Token) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Token operations
	RevokeToken(ctx context.Context, id uuid.UUID) error
	RevokeAllUserTokens(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) error
	RevokeAllUserTokensExcept(ctx context.Context, userID uuid.UUID, exceptTokenID uuid.UUID) error

	// Query operations
	GetUserTokens(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) ([]*entities.Token, error)
	GetValidToken(ctx context.Context, tokenHash string, tokenType entities.TokenType) (*entities.Token, error)
	CleanupExpiredTokens(ctx context.Context) error

	// Device and session management
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*entities.Token, error)
	RevokeDeviceTokens(ctx context.Context, userID uuid.UUID, deviceID string) error
}

// BlacklistRepository defines blacklist repository interface
type BlacklistRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, blacklist *entities.Blacklist) error
	GetByID(ctx context.Context, id uuid.UUID) (*entities.Blacklist, error)
	Update(ctx context.Context, blacklist *entities.Blacklist) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Blacklist operations
	IsBlacklisted(ctx context.Context, blacklistType entities.BlacklistType, value string) (bool, error)
	GetByTypeAndValue(ctx context.Context, blacklistType entities.BlacklistType, value string) (*entities.Blacklist, error)
	Deactivate(ctx context.Context, id uuid.UUID) error

	// Query operations
	List(ctx context.Context, blacklistType entities.BlacklistType, offset, limit int) ([]*entities.Blacklist, error)
	CleanupExpired(ctx context.Context) error

	// Bulk operations
	CheckMultiple(ctx context.Context, checks []struct {
		Type  entities.BlacklistType
		Value string
	}) (map[string]bool, error)
}

// PasswordHistoryRepository defines password history repository interface
type PasswordHistoryRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, history *entities.PasswordHistory) error
	GetUserPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]*entities.PasswordHistory, error)

	// Password validation
	IsPasswordReused(ctx context.Context, userID uuid.UUID, passwordHash string, checkCount int) (bool, error)

	// Cleanup operations
	CleanupOldPasswords(ctx context.Context, userID uuid.UUID, keepCount int) error
	CleanupExpiredPasswords(ctx context.Context, maxAge time.Duration) error
}
