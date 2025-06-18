package middleware

import (
	"github.com/gofiber/fiber/v2"
	"ms-auth/pkg/utils"
)

// RequireRole creates middleware that requires specific role
func RequireRole(requiredRole string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// For now, this is a simple role check
		// In a real implementation, you would:
		// 1. Get role_id from context
		// 2. Call MS-Authz service to check if role has required permissions
		// 3. Or implement local role checking

		roleID := c.Locals("role_id")
		if roleID == nil {
			return utils.ErrorResponse(c, 403, "Access denied: No role assigned", nil)
		}

		// TODO: Implement actual role checking logic
		// This could involve calling MS-Authz service or checking local role definitions

		// For demonstration, we'll assume admin role check
		if requiredRole == "admin" {
			// In real implementation, check if user has admin role
			// For now, we'll allow if role_id exists
			return c.Next()
		}

		return utils.ErrorResponse(c, 403, "Access denied: Insufficient permissions", nil)
	}
}

// RequirePermission creates middleware that requires specific permission
func RequirePermission(permission string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// This would typically call MS-Authz service to check permissions
		roleID := c.Locals("role_id")
		if roleID == nil {
			return utils.ErrorResponse(c, 403, "Access denied: No role assigned", nil)
		}

		// TODO: Call MS-Authz service to check permission
		// Example:
		// hasPermission, err := authzService.CheckPermission(roleID, permission)
		// if err != nil || !hasPermission {
		//     return utils.ErrorResponse(c, 403, "Access denied", nil)
		// }

		return c.Next()
	}
}

// RequireAnyRole creates middleware that requires any of the specified roles
func RequireAnyRole(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		roleID := c.Locals("role_id")
		if roleID == nil {
			return utils.ErrorResponse(c, 403, "Access denied: No role assigned", nil)
		}

		// TODO: Implement checking if user has any of the specified roles
		// For now, allow access if role_id exists
		return c.Next()
	}
}
