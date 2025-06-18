package services

import (
	"github.com/google/uuid"
	"ms-auth/internal/core/domain/entities"
	"ms-auth/pkg/utils"
	"time"
)

// TokenService defines token service interface
type TokenService interface {
	GenerateToken(userID uuid.UUID, tokenType entities.TokenType, duration time.Duration) (string, error)
	ValidateToken(tokenString string) (*entities.JWTClaims, error)
	GenerateResetToken(userID uuid.UUID) (string, error)
	GenerateVerificationToken(userID uuid.UUID, tokenType entities.TokenType) (string, error)
}

// JWTTokenService implements JWT token service
type JWTTokenService struct {
	secretKey string
	issuer    string
	audience  string
}

// NewJWTTokenService creates new JWT token service
func NewJWTTokenService(secretKey, issuer, audience string) *JWTTokenService {
	return &JWTTokenService{
		secretKey: secretKey,
		issuer:    issuer,
		audience:  audience,
	}
}

// GenerateToken generates JWT token
func (s *JWTTokenService) GenerateToken(userID uuid.UUID, tokenType entities.TokenType, duration time.Duration) (string, error) {
	now := time.Now()
	claims := &entities.JWTClaims{
		UserID:    userID,
		TokenID:   uuid.New(),
		TokenType: tokenType,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(duration).Unix(),
		NotBefore: now.Unix(),
		Issuer:    s.issuer,
		Audience:  s.audience,
	}

	return utils.GenerateJWT(claims, s.secretKey)
}

// ValidateToken validates JWT token
func (s *JWTTokenService) ValidateToken(tokenString string) (*entities.JWTClaims, error) {
	return utils.ValidateJWT(tokenString, s.secretKey)
}

// GenerateResetToken generates password reset token
func (s *JWTTokenService) GenerateResetToken(userID uuid.UUID) (string, error) {
	return s.GenerateToken(userID, entities.TokenTypePasswordReset, 1*time.Hour)
}

// GenerateVerificationToken generates verification token
func (s *JWTTokenService) GenerateVerificationToken(userID uuid.UUID, tokenType entities.TokenType) (string, error) {
	duration := 24 * time.Hour
	if tokenType == entities.TokenTypePhoneVerify {
		duration = 15 * time.Minute
	}
	return s.GenerateToken(userID, tokenType, duration)
}
