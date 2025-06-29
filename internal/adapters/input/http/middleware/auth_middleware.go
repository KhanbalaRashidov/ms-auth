package middleware

import (
	"github.com/gofiber/fiber/v2"
	"ms-auth/internal/core/domain/entities"
	"ms-auth/internal/core/ports/input"
	"ms-auth/pkg/utils"
	"strings"
)

// AuthMiddleware creates authentication middleware for normal access tokens
func AuthMiddleware(authUseCase input.AuthUseCase) fiber.Handler {
	return authMiddleware(authUseCase, entities.TokenTypeAccess)
}

// MFAAuthMiddleware creates authentication middleware for MFA challenge tokens
func MFAAuthMiddleware(authUseCase input.AuthUseCase) fiber.Handler {
	return authMiddleware(authUseCase, entities.TokenTypeMFAChallenge)
}

// OptionalAuthMiddleware creates optional authentication middleware
func OptionalAuthMiddleware(authUseCase input.AuthUseCase) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Next()
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Next()
		}

		token := parts[1]
		if token == "" {
			return c.Next()
		}

		claims, err := authUseCase.ValidateToken(c.Context(), token, entities.TokenTypeAccess)
		if err != nil {
			return c.Next()
		}

		c.Locals("user_id", claims.UserID.String())
		c.Locals("username", claims.Username)
		c.Locals("email", claims.Email)
		c.Locals("role", claims.Role)
		if claims.GroupID != nil {
			c.Locals("group_id", claims.GroupID.String())
		}

		return c.Next()
	}
}

// authMiddleware is the common authentication middleware logic
func authMiddleware(authUseCase input.AuthUseCase, expectedTokenType entities.TokenType) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return utils.ErrorResponse(c, 401, "Authorization header required", nil)
		}

		// Check Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return utils.ErrorResponse(c, 401, "Invalid authorization header format", nil)
		}

		token := parts[1]
		if token == "" {
			return utils.ErrorResponse(c, 401, "Token required", nil)
		}

		// Validate token with expected type
		claims, err := authUseCase.ValidateToken(c.Context(), token, expectedTokenType)
		if err != nil {
			return utils.HandleServiceError(c, err)
		}

		// Set user info in context
		c.Locals("user_id", claims.UserID.String())
		c.Locals("username", claims.Username)
		c.Locals("email", claims.Email)
		c.Locals("role", claims.Role)
		if claims.GroupID != nil {
			c.Locals("group_id", claims.GroupID.String())
		}

		return c.Next()
	}
}
