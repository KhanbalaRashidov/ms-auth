package errors

import "errors"

// Domain errors
var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrUnauthorized       = errors.New("unauthorized")

	// User status errors
	ErrUserBlocked = errors.New("user is blocked")
	ErrUserBanned  = errors.New("user is banned")
	ErrUserLimited = errors.New("user is limited")
	ErrUserLocked  = errors.New("user account is temporarily locked")

	// Password errors
	ErrWeakPassword   = errors.New("password does not meet complexity requirements")
	ErrPasswordReused = errors.New("password has been used recently")

	// MFA errors
	ErrMFARequired    = errors.New("multi-factor authentication required")
	ErrInvalidMFACode = errors.New("invalid MFA code")

	// Blacklist errors
	ErrBlacklistedValue = errors.New("value is blacklisted")

	// Validation errors
	ErrInvalidInput     = errors.New("invalid input")
	ErrValidationFailed = errors.New("validation failed")

	// Resource errors
	ErrResourceNotFound   = errors.New("resource not found")
	ErrResourceExists     = errors.New("resource already exists")
	ErrResourceConflict   = errors.New("resource conflict")
	ErrInsufficientRights = errors.New("insufficient rights")

	// Rate limiting errors
	ErrTooManyRequests   = errors.New("too many requests")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

// IsAuthenticationError checks if error is authentication related
func IsAuthenticationError(err error) bool {
	return err == ErrInvalidCredentials ||
		err == ErrInvalidToken ||
		err == ErrTokenExpired ||
		err == ErrUnauthorized ||
		err == ErrMFARequired ||
		err == ErrInvalidMFACode
}

// IsUserStatusError checks if error is user status related
func IsUserStatusError(err error) bool {
	return err == ErrUserBlocked ||
		err == ErrUserBanned ||
		err == ErrUserLimited ||
		err == ErrUserLocked
}

// IsValidationError checks if error is validation related
func IsValidationError(err error) bool {
	return err == ErrInvalidInput ||
		err == ErrValidationFailed ||
		err == ErrWeakPassword ||
		err == ErrPasswordReused
}
