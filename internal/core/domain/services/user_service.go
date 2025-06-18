package services

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"ms-auth/internal/core/domain/entities"
	"ms-auth/internal/core/ports/input"
	"ms-auth/internal/core/ports/output"
)

// UserService implements user business logic
type UserService struct {
	userRepo  output.UserRepository
	tokenRepo output.TokenRepository
}

// NewUserService creates new user service
func NewUserService(userRepo output.UserRepository, tokenRepo output.TokenRepository) input.UserUseCase {
	return &UserService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
	}
}

// GetUser gets user by ID
func (s *UserService) GetUser(ctx context.Context, userID uuid.UUID) (*entities.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// GetUserByIdentifier gets user by identifier
func (s *UserService) GetUserByIdentifier(ctx context.Context, identifier string) (*entities.User, error) {
	user, err := s.userRepo.GetByIdentifier(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// UpdateUserStatus updates user status
func (s *UserService) UpdateUserStatus(ctx context.Context, req *input.UpdateUserStatusRequest) error {
	// Check if user exists
	user, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Validate status transition
	if err := s.validateStatusTransition(user.Status, req.Status); err != nil {
		return err
	}

	// Update status
	if err := s.userRepo.UpdateStatus(ctx, req.UserID, req.Status); err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}

	// If user is blocked, banned, or deactivated, revoke all tokens
	if req.Status == entities.UserStatusBlocked ||
		req.Status == entities.UserStatusBanned ||
		req.Status == entities.UserStatusInactive {
		s.tokenRepo.RevokeAllUserTokens(ctx, req.UserID, entities.TokenTypeAccess)
		s.tokenRepo.RevokeAllUserTokens(ctx, req.UserID, entities.TokenTypeRefresh)
	}

	return nil
}

// UpdateUserParams updates user role and group
func (s *UserService) UpdateUserParams(ctx context.Context, req *input.UpdateUserParamsRequest) error {
	// Check if user exists
	_, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Update parameters
	if err := s.userRepo.UpdateUserParams(ctx, req.UserID, req.RoleID, req.GroupID); err != nil {
		return fmt.Errorf("failed to update user params: %w", err)
	}

	return nil
}

// DeleteUser deletes user (soft or hard delete)
func (s *UserService) DeleteUser(ctx context.Context, userID uuid.UUID, soft bool) error {
	// Check if user exists
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Revoke all tokens before deletion
	s.tokenRepo.RevokeAllUserTokens(ctx, userID, entities.TokenTypeAccess)
	s.tokenRepo.RevokeAllUserTokens(ctx, userID, entities.TokenTypeRefresh)

	// Delete user
	if soft {
		return s.userRepo.SoftDelete(ctx, userID)
	}
	return s.userRepo.Delete(ctx, userID)
}

// UpdateProfile updates user profile
func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error {
	// Get current user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Apply updates
	if firstName, ok := updates["first_name"].(string); ok {
		user.FirstName = firstName
	}
	if lastName, ok := updates["last_name"].(string); ok {
		user.LastName = lastName
	}
	if avatar, ok := updates["avatar"].(string); ok {
		user.Avatar = &avatar
	}
	if metadata, ok := updates["metadata"].(map[string]interface{}); ok {
		user.Metadata = metadata
	}

	// Update user
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update profile: %w", err)
	}

	return nil
}

// SendEmailVerification sends email verification
func (s *UserService) SendEmailVerification(ctx context.Context, userID uuid.UUID) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if user.EmailVerified {
		return errors.New("email already verified")
	}

	// TODO: Generate verification token and send email
	// This would typically integrate with an email service

	return nil
}

// VerifyEmail verifies email with token
func (s *UserService) VerifyEmail(ctx context.Context, token string) error {
	// TODO: Validate verification token and get user ID
	// For now, this is a placeholder

	return errors.New("not implemented")
}

// SendPhoneVerification sends phone verification code
func (s *UserService) SendPhoneVerification(ctx context.Context, userID uuid.UUID) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if user.PhoneVerified {
		return errors.New("phone already verified")
	}

	if user.Phone == nil {
		return errors.New("no phone number associated with account")
	}

	// TODO: Generate verification code and send SMS
	// This would typically integrate with an SMS service

	return nil
}

// VerifyPhone verifies phone with code
func (s *UserService) VerifyPhone(ctx context.Context, userID uuid.UUID, code string) error {
	// TODO: Validate verification code
	// For now, this is a placeholder

	// Mark phone as verified
	return s.userRepo.MarkPhoneVerified(ctx, userID)
}

// GetUserSessions gets user active sessions
func (s *UserService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*entities.Token, error) {
	sessions, err := s.tokenRepo.GetUserSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	return sessions, nil
}

// RevokeSession revokes specific user session
func (s *UserService) RevokeSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	// Get session to verify it belongs to the user
	session, err := s.tokenRepo.GetByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}

	if session.UserID != userID {
		return errors.New("session does not belong to user")
	}

	// Revoke session
	return s.tokenRepo.RevokeToken(ctx, sessionID)
}

// RevokeAllSessions revokes all user sessions
func (s *UserService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	return s.tokenRepo.RevokeAllUserTokens(ctx, userID, entities.TokenTypeRefresh)
}

// validateStatusTransition validates if status transition is allowed
func (s *UserService) validateStatusTransition(current, new entities.UserStatus) error {
	// Define allowed transitions
	allowedTransitions := map[entities.UserStatus][]entities.UserStatus{
		entities.UserStatusActive: {
			entities.UserStatusBlocked,
			entities.UserStatusBanned,
			entities.UserStatusLimited,
			entities.UserStatusInactive,
		},
		entities.UserStatusBlocked: {
			entities.UserStatusActive,
			entities.UserStatusBanned,
			entities.UserStatusInactive,
		},
		entities.UserStatusBanned: {
			entities.UserStatusActive, // Only if unbanned by admin
		},
		entities.UserStatusLimited: {
			entities.UserStatusActive,
			entities.UserStatusBlocked,
			entities.UserStatusBanned,
			entities.UserStatusInactive,
		},
		entities.UserStatusInactive: {
			entities.UserStatusActive,
		},
	}

	allowed, exists := allowedTransitions[current]
	if !exists {
		return fmt.Errorf("invalid current status: %d", current)
	}

	for _, allowedStatus := range allowed {
		if allowedStatus == new {
			return nil
		}
	}

	return fmt.Errorf("status transition from %d to %d is not allowed", current, new)
}
