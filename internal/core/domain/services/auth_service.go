package services

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	"ms-auth/internal/core/domain/entities"
	"ms-auth/internal/core/ports/input"
	"ms-auth/internal/core/ports/output"
	"ms-auth/pkg/utils"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserBlocked        = errors.New("user is blocked")
	ErrUserBanned         = errors.New("user is banned")
	ErrUserLimited        = errors.New("user is limited")
	ErrUserLocked         = errors.New("user account is temporarily locked")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrMFARequired        = errors.New("multi-factor authentication required")
	ErrInvalidMFACode     = errors.New("invalid MFA code")
	ErrWeakPassword       = errors.New("password does not meet complexity requirements")
	ErrPasswordReused     = errors.New("password has been used recently")
	ErrBlacklistedValue   = errors.New("value is blacklisted")
)

// AuthService implements authentication business logic
type AuthService struct {
	userRepo            output.UserRepository
	tokenRepo           output.TokenRepository
	blacklistRepo       output.BlacklistRepository
	passwordHistoryRepo output.PasswordHistoryRepository
	tokenService        TokenService
	passwordService     PasswordService
	otpService          OTPService
}

// NewAuthService creates new auth service
func NewAuthService(
	userRepo output.UserRepository,
	tokenRepo output.TokenRepository,
	blacklistRepo output.BlacklistRepository,
	passwordHistoryRepo output.PasswordHistoryRepository,
	tokenService TokenService,
	passwordService PasswordService,
	otpService OTPService,
) input.AuthUseCase {
	return &AuthService{
		userRepo:            userRepo,
		tokenRepo:           tokenRepo,
		blacklistRepo:       blacklistRepo,
		passwordHistoryRepo: passwordHistoryRepo,
		tokenService:        tokenService,
		passwordService:     passwordService,
		otpService:          otpService,
	}
}

// Register implements user registration
func (s *AuthService) Register(ctx context.Context, req *input.RegisterRequest) (*entities.User, error) {
	// Check blacklist
	if err := s.checkBlacklist(ctx, req); err != nil {
		return nil, err
	}

	// Check if user exists
	if exists, _ := s.userRepo.ExistsByUsername(ctx, req.Username); exists {
		return nil, errors.New("username already exists")
	}

	if exists, _ := s.userRepo.ExistsByEmail(ctx, req.Email); exists {
		return nil, errors.New("email already exists")
	}

	if req.Phone != "" {
		if exists, _ := s.userRepo.ExistsByPhone(ctx, req.Phone); exists {
			return nil, errors.New("phone number already exists")
		}
	}

	// Validate password complexity
	if err := s.passwordService.ValidateComplexity(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	passwordHash, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &entities.User{
		ID:           uuid.New(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Status:       entities.UserStatusActive,
	}

	if req.Phone != "" {
		user.Phone = &req.Phone
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Save password to history
	passwordHistory := &entities.PasswordHistory{
		UserID:       user.ID,
		PasswordHash: passwordHash,
	}
	s.passwordHistoryRepo.Create(ctx, passwordHistory)

	return user, nil
}

// Login implements user login
func (s *AuthService) Login(ctx context.Context, req *input.LoginRequest) (*input.LoginResponse, error) {
	// Get user by identifier
	user, err := s.userRepo.GetByIdentifier(ctx, req.Identifier)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Check if user can login
	if !user.CanLogin() {
		if user.IsBanned() {
			return nil, ErrUserBanned
		}
		if user.IsBlocked() {
			return nil, ErrUserBlocked
		}
		if user.IsLimited() {
			return nil, ErrUserLimited
		}
		if user.IsLocked() {
			return nil, ErrUserLocked
		}
		return nil, errors.New("user cannot login")
	}

	// Verify password
	if !s.passwordService.VerifyPassword(req.Password, user.PasswordHash) {
		// Increment login attempts
		user.IncrementLoginAttempts()
		s.userRepo.UpdateLoginAttempts(ctx, user.ID, user.LoginAttempts, user.LockedUntil)
		return nil, ErrInvalidCredentials
	}

	// Reset login attempts on successful login
	user.ResetLoginAttempts()
	s.userRepo.UpdateLoginAttempts(ctx, user.ID, 0, nil)

	// Check if MFA is required
	// AuthService.Login metodunda
	// AuthService.Login metodunda MFA hissəsi
	if user.TwoFactorEnabled {
		// Generate MFA challenge token
		challengeToken, err := s.tokenService.GenerateToken(user, entities.TokenTypeMFAChallenge, 15*time.Minute)
		if err != nil {
			return nil, fmt.Errorf("failed to generate MFA challenge: %w", err)
		}

		// Challenge token-i verilənlər bazasında saxla
		now := time.Now()
		challengeTokenEntity := &entities.Token{
			UserID:    user.ID,
			TokenHash: utils.HashSHA256(challengeToken),
			Type:      entities.TokenTypeMFAChallenge,
			ExpiresAt: now.Add(15 * time.Minute),
			DeviceID:  &req.DeviceID,
			UserAgent: &req.UserAgent,
			IPAddress: &req.IPAddress,
		}

		if err := s.tokenRepo.Create(ctx, challengeTokenEntity); err != nil {
			return nil, fmt.Errorf("failed to save MFA challenge token: %w", err)
		}

		return &input.LoginResponse{
			User:         user,
			RequiresMFA:  true,
			MFAChallenge: challengeToken,
		}, nil
	}
	// Generate token pair
	tokenPair, err := s.generateTokenPair(ctx, user, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login
	user.UpdateLastLogin(req.IPAddress)
	s.userRepo.UpdateLastLogin(ctx, user.ID, *user.LastLoginAt, req.IPAddress)

	return &input.LoginResponse{
		User:        user,
		TokenPair:   tokenPair,
		RequiresMFA: false,
	}, nil
}

// RefreshToken implements token refresh
func (s *AuthService) RefreshToken(ctx context.Context, req *input.RefreshTokenRequest) (*entities.TokenPair, error) {
	// Parse and validate refresh token
	claims, err := s.tokenService.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if claims.TokenType != entities.TokenTypeRefresh {
		return nil, ErrInvalidToken
	}

	// Get token from database
	tokenHash := utils.HashSHA256(req.RefreshToken)
	token, err := s.tokenRepo.GetValidToken(ctx, tokenHash, entities.TokenTypeRefresh)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if !token.IsValid() {
		return nil, ErrTokenExpired
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, token.UserID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if !user.CanLogin() {
		return nil, ErrUserBlocked
	}

	// Revoke old refresh token
	s.tokenRepo.RevokeToken(ctx, token.ID)

	// Generate new token pair
	loginReq := &input.LoginRequest{
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
		IPAddress: req.IPAddress,
		Remember:  true, // Refresh tokens are long-lived
	}

	return s.generateTokenPair(ctx, user, loginReq)
}

// Logout implements user logout
func (s *AuthService) Logout(ctx context.Context, userID uuid.UUID, req *input.LogoutRequest) error {
	if req.LogoutAll {
		// Revoke all user tokens
		return s.tokenRepo.RevokeAllUserTokens(ctx, userID, entities.TokenTypeRefresh)
	}

	if req.RefreshToken != "" {
		// Revoke specific token
		tokenHash := utils.HashSHA256(req.RefreshToken)
		token, err := s.tokenRepo.GetByHash(ctx, tokenHash)
		if err == nil {
			return s.tokenRepo.RevokeToken(ctx, token.ID)
		}
	}

	return nil
}

// ForgotPassword implements forgot password
func (s *AuthService) ForgotPassword(ctx context.Context, req *input.ForgotPasswordRequest) error {
	// Get user by identifier
	user, err := s.userRepo.GetByIdentifier(ctx, req.Identifier)
	if err != nil {
		// Don't reveal if user exists or not for security
		return nil
	}

	// Generate reset token
	resetToken, err := s.tokenService.GenerateResetToken(user)
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Save reset token to database
	now := time.Now()
	tokenEntity := &entities.Token{
		UserID:    user.ID,
		TokenHash: utils.HashSHA256(resetToken),
		Type:      entities.TokenTypePasswordReset,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	if err := s.tokenRepo.Create(ctx, tokenEntity); err != nil {
		return fmt.Errorf("failed to save reset token: %w", err)
	}

	// TODO: Send reset email with token
	// This would integrate with email service

	return nil
}

// ResetPassword implements password reset
func (s *AuthService) ResetPassword(ctx context.Context, req *input.ResetPasswordRequest) error {
	// Validate reset token
	claims, err := s.tokenService.ValidateToken(req.Token)
	if err != nil {
		return ErrInvalidToken
	}

	if claims.TokenType != entities.TokenTypePasswordReset {
		return ErrInvalidToken
	}

	// Get token from database
	tokenHash := utils.HashSHA256(req.Token)
	token, err := s.tokenRepo.GetValidToken(ctx, tokenHash, entities.TokenTypePasswordReset)
	if err != nil {
		return ErrInvalidToken
	}

	if !token.IsValid() {
		return ErrTokenExpired
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, token.UserID)
	if err != nil {
		return ErrUserNotFound
	}

	// Validate new password complexity
	if err := s.passwordService.ValidateComplexity(req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	newPasswordHash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Check password reuse
	isReused, err := s.passwordHistoryRepo.IsPasswordReused(ctx, user.ID, newPasswordHash, 5)
	if err == nil && isReused {
		return ErrPasswordReused
	}

	// Update password
	if err := s.userRepo.UpdatePassword(ctx, user.ID, newPasswordHash); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Save to password history
	passwordHistory := &entities.PasswordHistory{
		UserID:       user.ID,
		PasswordHash: newPasswordHash,
	}
	s.passwordHistoryRepo.Create(ctx, passwordHistory)

	// Revoke reset token
	s.tokenRepo.RevokeToken(ctx, token.ID)

	// Revoke all user tokens to force re-login
	s.tokenRepo.RevokeAllUserTokens(ctx, user.ID, entities.TokenTypeRefresh)
	s.tokenRepo.RevokeAllUserTokens(ctx, user.ID, entities.TokenTypeAccess)

	return nil
}

// RevokeToken revokes specific token
func (s *AuthService) RevokeToken(ctx context.Context, tokenID uuid.UUID) error {
	return s.tokenRepo.RevokeToken(ctx, tokenID)
}

// RevokeAllUserTokens revokes all user tokens
func (s *AuthService) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	// Revoke both access and refresh tokens
	if err := s.tokenRepo.RevokeAllUserTokens(ctx, userID, entities.TokenTypeAccess); err != nil {
		return err
	}
	return s.tokenRepo.RevokeAllUserTokens(ctx, userID, entities.TokenTypeRefresh)
}

// EnableMFA enables multi-factor authentication
func (s *AuthService) EnableMFA(ctx context.Context, userID uuid.UUID, req *input.EnableMFARequest) (*input.EnableMFAResponse, error) {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Verify password
	if !s.passwordService.VerifyPassword(req.Password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	// Generate TOTP secret
	secret, err := s.otpService.GenerateSecret(user.Email, "MS-Auth")
	if err != nil {
		return nil, fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	// Generate QR code
	qrCode, err := s.otpService.GenerateQRCode(secret, user.Email, "MS-Auth")
	log.Println(qrCode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Generate backup codes
	backupCodes := s.otpService.GenerateBackupCodes(8)

	// Enable MFA for user
	if err := s.userRepo.EnableTwoFactor(ctx, userID, secret); err != nil {
		return nil, fmt.Errorf("failed to enable MFA: %w", err)
	}

	return &input.EnableMFAResponse{
		Secret:      secret,
		QRCode:      qrCode,
		BackupCodes: backupCodes,
	}, nil
}

// DisableMFA disables multi-factor authentication
func (s *AuthService) DisableMFA(ctx context.Context, userID uuid.UUID, password string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Verify password
	if !s.passwordService.VerifyPassword(password, user.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Disable MFA
	return s.userRepo.DisableTwoFactor(ctx, userID)
}

// VerifyMFA verifies MFA code
func (s *AuthService) VerifyMFA(ctx context.Context, userID uuid.UUID, req *input.VerifyMFARequest) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	if !user.TwoFactorEnabled || user.TwoFactorSecret == nil {
		return errors.New("MFA not enabled")
	}

	// Validate TOTP code
	if !s.otpService.ValidateCode(*user.TwoFactorSecret, req.Code) {
		return ErrInvalidMFACode
	}

	return nil
}

// MFA verify ediləndən sonra normal token pair yaradın
// AuthService-ə əlavə edin
func (s *AuthService) CompleteMFALogin(ctx context.Context, userID uuid.UUID, req *input.LoginRequest) (*entities.TokenPair, error) {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// MFA challenge token-lərini ləğv et
	s.tokenRepo.RevokeAllUserTokens(ctx, userID, entities.TokenTypeMFAChallenge)

	// Normal token pair yarat
	tokenPair, err := s.generateTokenPair(ctx, user, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login
	user.UpdateLastLogin(req.IPAddress)
	s.userRepo.UpdateLastLogin(ctx, user.ID, *user.LastLoginAt, req.IPAddress)

	return tokenPair, nil
}

// GenerateBackupCodes generates new backup codes
func (s *AuthService) GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if !user.TwoFactorEnabled {
		return nil, errors.New("MFA not enabled")
	}

	// Generate new backup codes
	backupCodes := s.otpService.GenerateBackupCodes(8)

	// TODO: Store backup codes securely
	// This would typically involve hashing and storing them

	return backupCodes, nil
}

// ChangePassword implements password change
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, req *input.ChangePasswordRequest) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Verify current password
	if !s.passwordService.VerifyPassword(req.CurrentPassword, user.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Validate new password complexity
	if err := s.passwordService.ValidateComplexity(req.NewPassword); err != nil {
		return err
	}

	// Check password reuse
	newPasswordHash, _ := s.passwordService.HashPassword(req.NewPassword)
	isReused, err := s.passwordHistoryRepo.IsPasswordReused(ctx, userID, newPasswordHash, 5)
	if err == nil && isReused {
		return ErrPasswordReused
	}

	// Update password
	if err := s.userRepo.UpdatePassword(ctx, userID, newPasswordHash); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Save to password history
	passwordHistory := &entities.PasswordHistory{
		UserID:       userID,
		PasswordHash: newPasswordHash,
	}
	s.passwordHistoryRepo.Create(ctx, passwordHistory)

	// Cleanup old passwords
	s.passwordHistoryRepo.CleanupOldPasswords(ctx, userID, 5)

	// Revoke all refresh tokens to force re-login
	s.tokenRepo.RevokeAllUserTokens(ctx, userID, entities.TokenTypeRefresh)

	return nil
}

// ValidateToken validates JWT token
func (s *AuthService) ValidateToken(ctx context.Context, tokenString string, tokenType entities.TokenType) (*entities.JWTClaims, error) {
	// Parse token
	claims, err := s.tokenService.ValidateToken(tokenString)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if claims.TokenType != tokenType {
		return nil, ErrInvalidToken
	}

	// Check if token exists in database and is valid
	tokenHash := utils.HashSHA256(tokenString)
	token, err := s.tokenRepo.GetValidToken(ctx, tokenHash, tokenType)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if !token.IsValid() {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

// generateTokenPair generates access and refresh token pair
func (s *AuthService) generateTokenPair(ctx context.Context, user *entities.User, req *input.LoginRequest) (*entities.TokenPair, error) {
	var accessTokenDuration, refreshTokenDuration time.Duration

	if req.Remember {
		accessTokenDuration = 24 * time.Hour
		refreshTokenDuration = 30 * 24 * time.Hour
	} else {
		accessTokenDuration = 1 * time.Hour
		refreshTokenDuration = 7 * 24 * time.Hour
	}

	// Generate access token
	accessToken, err := s.tokenService.GenerateToken(user, entities.TokenTypeAccess, accessTokenDuration)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := s.tokenService.GenerateToken(user, entities.TokenTypeRefresh, refreshTokenDuration)
	if err != nil {
		return nil, err
	}

	// Save tokens to database
	now := time.Now()

	accessTokenEntity := &entities.Token{
		UserID:    user.ID,
		TokenHash: utils.HashSHA256(accessToken),
		Type:      entities.TokenTypeAccess,
		ExpiresAt: now.Add(accessTokenDuration),
		DeviceID:  &req.DeviceID,
		UserAgent: &req.UserAgent,
		IPAddress: &req.IPAddress,
	}

	refreshTokenEntity := &entities.Token{
		UserID:    user.ID,
		TokenHash: utils.HashSHA256(refreshToken),
		Type:      entities.TokenTypeRefresh,
		ExpiresAt: now.Add(refreshTokenDuration),
		DeviceID:  &req.DeviceID,
		UserAgent: &req.UserAgent,
		IPAddress: &req.IPAddress,
	}

	if err := s.tokenRepo.Create(ctx, accessTokenEntity); err != nil {
		return nil, err
	}

	if err := s.tokenRepo.Create(ctx, refreshTokenEntity); err != nil {
		return nil, err
	}

	return &entities.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenDuration.Seconds()),
		ExpiresAt:    now.Add(accessTokenDuration),
		IssuedAt:     now,
	}, nil
}

// checkBlacklist checks if registration data is blacklisted
func (s *AuthService) checkBlacklist(ctx context.Context, req *input.RegisterRequest) error {
	checks := map[entities.BlacklistType]string{
		entities.BlacklistTypeEmail:    req.Email,
		entities.BlacklistTypeUsername: req.Username,
	}

	if req.Phone != "" {
		checks[entities.BlacklistTypePhone] = req.Phone
	}

	for blacklistType, value := range checks {
		if blacklisted, _ := s.blacklistRepo.IsBlacklisted(ctx, blacklistType, value); blacklisted {
			return fmt.Errorf("%s is blacklisted", string(blacklistType))
		}
	}

	return nil
}
