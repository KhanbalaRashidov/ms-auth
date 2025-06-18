package services

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"ms-auth/internal/core/domain/entities"
	"ms-auth/internal/core/ports/input"
	"ms-auth/internal/core/ports/output"
)

// BlacklistService implements blacklist business logic
type BlacklistService struct {
	blacklistRepo output.BlacklistRepository
}

// NewBlacklistService creates new blacklist service
func NewBlacklistService(blacklistRepo output.BlacklistRepository) input.BlacklistUseCase {
	return &BlacklistService{
		blacklistRepo: blacklistRepo,
	}
}

// IsBlacklisted checks if value is blacklisted
func (s *BlacklistService) IsBlacklisted(ctx context.Context, blacklistType entities.BlacklistType, value string) (bool, error) {
	return s.blacklistRepo.IsBlacklisted(ctx, blacklistType, value)
}

// CheckMultiple checks multiple values for blacklisting
func (s *BlacklistService) CheckMultiple(ctx context.Context, checks map[entities.BlacklistType]string) (map[string]bool, error) {
	checkSlice := make([]struct {
		Type  entities.BlacklistType
		Value string
	}, 0, len(checks))

	for blacklistType, value := range checks {
		checkSlice = append(checkSlice, struct {
			Type  entities.BlacklistType
			Value string
		}{Type: blacklistType, Value: value})
	}

	return s.blacklistRepo.CheckMultiple(ctx, checkSlice)
}

// AddToBlacklist adds value to blacklist
func (s *BlacklistService) AddToBlacklist(ctx context.Context, blacklistType entities.BlacklistType, value, reason string) error {
	// Check if already blacklisted
	exists, err := s.blacklistRepo.IsBlacklisted(ctx, blacklistType, value)
	if err != nil {
		return fmt.Errorf("failed to check blacklist: %w", err)
	}

	if exists {
		return fmt.Errorf("value already blacklisted")
	}

	// Create blacklist entry
	blacklist := &entities.Blacklist{
		Type:     blacklistType,
		Value:    value,
		Reason:   reason,
		IsActive: true,
	}

	if err := s.blacklistRepo.Create(ctx, blacklist); err != nil {
		return fmt.Errorf("failed to add to blacklist: %w", err)
	}

	return nil
}

// RemoveFromBlacklist removes value from blacklist
func (s *BlacklistService) RemoveFromBlacklist(ctx context.Context, id uuid.UUID) error {
	// Check if blacklist entry exists
	_, err := s.blacklistRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("blacklist entry not found: %w", err)
	}

	// Deactivate blacklist entry
	if err := s.blacklistRepo.Deactivate(ctx, id); err != nil {
		return fmt.Errorf("failed to remove from blacklist: %w", err)
	}

	return nil
}

// GetBlacklist gets blacklist entries with pagination
func (s *BlacklistService) GetBlacklist(ctx context.Context, blacklistType entities.BlacklistType, offset, limit int) ([]*entities.Blacklist, error) {
	blacklists, err := s.blacklistRepo.List(ctx, blacklistType, offset, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get blacklist: %w", err)
	}
	return blacklists, nil
}
