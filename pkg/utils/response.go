package utils

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"net/http"
	"strings"
)

// APIResponse represents standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

// APIError represents API error
type APIError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// SuccessResponse returns success response
func SuccessResponse(c *fiber.Ctx, status int, message string, data interface{}) error {
	return c.Status(status).JSON(APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// ErrorResponse returns error response
func ErrorResponse(c *fiber.Ctx, status int, message string, err error) error {
	apiError := &APIError{
		Code:    getErrorCode(status),
		Message: message,
	}

	if err != nil {
		apiError.Details = err.Error()
	}

	return c.Status(status).JSON(APIResponse{
		Success: false,
		Error:   apiError,
	})
}

// ValidationErrorResponse returns validation error response
func ValidationErrorResponse(c *fiber.Ctx, err error) error {
	var errors []string

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, validationError := range validationErrors {
			errors = append(errors, getValidationErrorMessage(validationError))
		}
	} else {
		errors = append(errors, err.Error())
	}

	apiError := &APIError{
		Code:    "VALIDATION_ERROR",
		Message: "Validation failed",
		Details: errors,
	}

	return c.Status(http.StatusBadRequest).JSON(APIResponse{
		Success: false,
		Error:   apiError,
	})
}

// HandleServiceError handles service layer errors
func HandleServiceError(c *fiber.Ctx, err error) error {
	errMsg := err.Error()

	// Map common service errors to HTTP status codes
	switch {
	case strings.Contains(errMsg, "not found"):
		return ErrorResponse(c, http.StatusNotFound, "Resource not found", err)
	case strings.Contains(errMsg, "invalid credentials"):
		return ErrorResponse(c, http.StatusUnauthorized, "Invalid credentials", err)
	case strings.Contains(errMsg, "unauthorized"):
		return ErrorResponse(c, http.StatusUnauthorized, "Unauthorized", err)
	case strings.Contains(errMsg, "forbidden"):
		return ErrorResponse(c, http.StatusForbidden, "Forbidden", err)
	case strings.Contains(errMsg, "already exists"):
		return ErrorResponse(c, http.StatusConflict, "Resource already exists", err)
	case strings.Contains(errMsg, "blocked"):
		return ErrorResponse(c, http.StatusForbidden, "User is blocked", err)
	case strings.Contains(errMsg, "banned"):
		return ErrorResponse(c, http.StatusForbidden, "User is banned", err)
	case strings.Contains(errMsg, "locked"):
		return ErrorResponse(c, http.StatusForbidden, "User account is locked", err)
	case strings.Contains(errMsg, "blacklisted"):
		return ErrorResponse(c, http.StatusForbidden, "Value is blacklisted", err)
	case strings.Contains(errMsg, "expired"):
		return ErrorResponse(c, http.StatusUnauthorized, "Token expired", err)
	case strings.Contains(errMsg, "invalid token"):
		return ErrorResponse(c, http.StatusUnauthorized, "Invalid token", err)
	case strings.Contains(errMsg, "weak password"):
		return ErrorResponse(c, http.StatusBadRequest, "Password does not meet complexity requirements", err)
	case strings.Contains(errMsg, "password reused"):
		return ErrorResponse(c, http.StatusBadRequest, "Password has been used recently", err)
	case strings.Contains(errMsg, "MFA required"):
		return ErrorResponse(c, http.StatusUnauthorized, "Multi-factor authentication required", err)
	case strings.Contains(errMsg, "invalid MFA"):
		return ErrorResponse(c, http.StatusBadRequest, "Invalid MFA code", err)
	default:
		return ErrorResponse(c, http.StatusInternalServerError, "Internal server error", err)
	}
}

// getErrorCode returns error code based on HTTP status
func getErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusTooManyRequests:
		return "TOO_MANY_REQUESTS"
	case http.StatusInternalServerError:
		return "INTERNAL_SERVER_ERROR"
	default:
		return "UNKNOWN_ERROR"
	}
}

// getValidationErrorMessage returns user-friendly validation error message
func getValidationErrorMessage(err validator.FieldError) string {
	field := strings.ToLower(err.Field())

	switch err.Tag() {
	case "required":
		return field + " is required"
	case "email":
		return field + " must be a valid email address"
	case "min":
		return field + " must be at least " + err.Param() + " characters long"
	case "max":
		return field + " must be at most " + err.Param() + " characters long"
	case "len":
		return field + " must be exactly " + err.Param() + " characters long"
	case "alphanum":
		return field + " must contain only alphanumeric characters"
	case "numeric":
		return field + " must contain only numeric characters"
	case "e164":
		return field + " must be a valid phone number"
	default:
		return field + " is invalid"
	}
}

// ParseUUID parses string to UUID
func ParseUUID(s string) uuid.UUID {
	id, _ := uuid.Parse(s)
	return id
}
