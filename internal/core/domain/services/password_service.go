package services

import (
	"errors"
	"ms-auth/internal/core/domain/entities"
	"ms-auth/pkg/utils"
	_ "regexp"
	"strings"
	"unicode"
)

// PasswordService defines password service interface
type PasswordService interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) bool
	ValidateComplexity(password string) error
	GenerateRandomPassword(length int) string
}

// BCryptPasswordService implements password service using bcrypt
type BCryptPasswordService struct {
	complexity entities.PasswordComplexity
}

// NewBCryptPasswordService creates new bcrypt password service
func NewBCryptPasswordService(complexity entities.PasswordComplexity) *BCryptPasswordService {
	return &BCryptPasswordService{
		complexity: complexity,
	}
}

// HashPassword hashes password using bcrypt
func (s *BCryptPasswordService) HashPassword(password string) (string, error) {
	return utils.HashPassword(password)
}

// VerifyPassword verifies password against hash
func (s *BCryptPasswordService) VerifyPassword(password, hash string) bool {
	return utils.CheckPasswordHash(password, hash)
}

// ValidateComplexity validates password complexity
func (s *BCryptPasswordService) ValidateComplexity(password string) error {
	// Check length
	if len(password) < s.complexity.MinLength {
		return errors.New("password too short")
	}

	if len(password) > s.complexity.MaxLength {
		return errors.New("password too long")
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasDigit   = false
		hasSpecial = false
	)

	// Check character requirements
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case isSpecialChar(char):
			hasSpecial = true
		}
	}

	if s.complexity.RequireUpper && !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}

	if s.complexity.RequireLower && !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}

	if s.complexity.RequireDigit && !hasDigit {
		return errors.New("password must contain at least one digit")
	}

	if s.complexity.RequireSpecial && !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	// Check for common weak patterns
	if err := s.checkWeakPatterns(password); err != nil {
		return err
	}

	return nil
}

// GenerateRandomPassword generates random password
func (s *BCryptPasswordService) GenerateRandomPassword(length int) string {
	return utils.GenerateRandomString(length)
}

// checkWeakPatterns checks for common weak password patterns
func (s *BCryptPasswordService) checkWeakPatterns(password string) error {
	lower := strings.ToLower(password)

	// Check for common weak passwords
	weakPasswords := []string{
		"password", "123456", "qwerty", "abc123", "admin", "user",
		"test", "guest", "root", "login", "pass", "welcome",
	}

	for _, weak := range weakPasswords {
		if strings.Contains(lower, weak) {
			return errors.New("password contains common weak patterns")
		}
	}

	// Check for keyboard patterns
	keyboardPatterns := []string{
		"qwerty", "asdfgh", "zxcvbn", "123456", "654321",
		"qwertyuiop", "asdfghjkl", "zxcvbnm",
	}

	for _, pattern := range keyboardPatterns {
		if strings.Contains(lower, pattern) {
			return errors.New("password contains keyboard patterns")
		}
	}

	// Check for repeated characters
	if hasRepeatedChars(password, 3) {
		return errors.New("password contains too many repeated characters")
	}

	// Check for sequential characters
	if hasSequentialChars(password, 3) {
		return errors.New("password contains sequential characters")
	}

	return nil
}

// isSpecialChar checks if character is special
func isSpecialChar(char rune) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	return strings.ContainsRune(specialChars, char)
}

// hasRepeatedChars checks for repeated characters
func hasRepeatedChars(password string, maxRepeats int) bool {
	if len(password) < maxRepeats {
		return false
	}

	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count >= maxRepeats {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}

// hasSequentialChars checks for sequential characters
func hasSequentialChars(password string, maxSequential int) bool {
	if len(password) < maxSequential {
		return false
	}

	for i := 0; i <= len(password)-maxSequential; i++ {
		isSequential := true
		isReverseSequential := true

		for j := 1; j < maxSequential; j++ {
			if password[i+j] != password[i]+byte(j) {
				isSequential = false
			}
			if password[i+j] != password[i]-byte(j) {
				isReverseSequential = false
			}
		}

		if isSequential || isReverseSequential {
			return true
		}
	}
	return false
}
