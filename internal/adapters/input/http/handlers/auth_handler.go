package handlers

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"ms-auth/internal/core/ports/input"
	"ms-auth/pkg/utils"
	"net/http"
)

// AuthHandler handles authentication requests
type AuthHandler struct {
	authUseCase input.AuthUseCase
	userUseCase input.UserUseCase
	validator   *validator.Validate
}

// DisableMFARequest is a request body for disabling MFA
type DisableMFARequest struct {
	Password string `json:"password" validate:"required"`
}

// NewAuthHandler creates new auth handler
func NewAuthHandler(authUseCase input.AuthUseCase, userUseCase input.UserUseCase) *AuthHandler {
	return &AuthHandler{
		authUseCase: authUseCase,
		userUseCase: userUseCase,
		validator:   validator.New(),
	}
}

// Register
// @Summary Register a new user
// @Description Register a new user with email and password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body input.RegisterRequest true "Register Request"
// @Success 201 {object} utils.APIResponse{data=object} "User registered successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body or validation error"
// @Failure 409 {object} utils.APIResponse{error=utils.APIError} "User with email already exists"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req input.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	user, err := h.authUseCase.Register(c.Context(), &req)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusCreated, "User registered successfully", user)
}

// Login
// @Summary Log in a user
// @Description Authenticate user with email and password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body input.LoginRequest true "Login Request"
// @Success 200 {object} utils.APIResponse{data=object} "Login successful"
// @Success 200 {object} utils.APIResponse{data=map[string]interface{}} "MFA required"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body or validation error"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Invalid credentials"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req input.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	// Set IP address and user agent
	req.IPAddress = c.IP()
	req.UserAgent = string(c.Request().Header.UserAgent())

	response, err := h.authUseCase.Login(c.Context(), &req)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	if response.RequiresMFA {
		return utils.SuccessResponse(c, http.StatusOK, "MFA required", map[string]interface{}{
			"requires_mfa": true,
			"challenge":    response.MFAChallenge,
		})
	}

	return utils.SuccessResponse(c, http.StatusOK, "Login successful", response)
}

// RefreshToken
// @Summary Refresh access token
// @Description Refresh access token using a refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body input.RefreshTokenRequest true "Refresh Token Request"
// @Success 200 {object} utils.APIResponse{data=object} "Token refreshed successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body or validation error"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Invalid or expired refresh token"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var req input.RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	// Set IP address and user agent
	req.IPAddress = c.IP()
	req.UserAgent = string(c.Request().Header.UserAgent())

	tokenPair, err := h.authUseCase.RefreshToken(c.Context(), &req)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Token refreshed successfully", tokenPair)
}

// Logout
// @Summary Log out a user
// @Description Invalidate user's session and refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body input.LogoutRequest false "Logout Request (optional)"
// @Success 200 {object} utils.APIResponse{data=object} "Logout successful"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req input.LogoutRequest
	if err := c.BodyParser(&req); err != nil {
		// If no body, create empty request
		req = input.LogoutRequest{}
	}

	if err := h.authUseCase.Logout(c.Context(), utils.ParseUUID(userID), &req); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Logout successful", nil)
}

// ChangePassword
// @Summary Change user password
// @Description Allows a logged-in user to change their password
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body input.ChangePasswordRequest true "Change Password Request"
// @Success 200 {object} utils.APIResponse{data=object} "Password changed successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body or validation error"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized or invalid current password"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/change-password [post]
func (h *AuthHandler) ChangePassword(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req input.ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	if err := h.authUseCase.ChangePassword(c.Context(), utils.ParseUUID(userID), &req); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Password changed successfully", nil)
}

// ForgotPassword
// @Summary Request password reset
// @Description Initiates the password reset process by sending an email with a reset link
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body input.ForgotPasswordRequest true "Forgot Password Request"
// @Success 200 {object} utils.APIResponse{data=object} "Password reset email sent"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body or validation error"
// @Failure 404 {object} utils.APIResponse{error=utils.APIError} "User not found"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *fiber.Ctx) error {
	var req input.ForgotPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	if err := h.authUseCase.ForgotPassword(c.Context(), &req); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Password reset email sent", nil)
}

// ResetPassword
// @Summary Reset user password
// @Description Resets the user's password using a valid reset token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body input.ResetPasswordRequest true "Reset Password Request"
// @Success 200 {object} utils.APIResponse{data=object} "Password reset successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body, validation error, or invalid/expired token"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *fiber.Ctx) error {
	var req input.ResetPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	if err := h.authUseCase.ResetPassword(c.Context(), &req); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Password reset successfully", nil)
}

// EnableMFA
// @Summary Enable Multi-Factor Authentication (MFA)
// @Description Enables MFA for the logged-in user
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body input.EnableMFARequest true "Enable MFA Request"
// @Success 200 {object} utils.APIResponse{data=object} "MFA enabled successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body or validation error"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/mfa/enable [post]
func (h *AuthHandler) EnableMFA(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req input.EnableMFARequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	response, err := h.authUseCase.EnableMFA(c.Context(), utils.ParseUUID(userID), &req)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "MFA enabled successfully", response)
}

// DisableMFA
// @Summary Disable Multi-Factor Authentication (MFA)
// @Description Disables MFA for the logged-in user
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body DisableMFARequest true "Disable MFA Request"
// @Success 200 {object} utils.APIResponse{data=object} "MFA disabled successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body or validation error"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized or invalid password"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/mfa/disable [post]
func (h *AuthHandler) DisableMFA(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req DisableMFARequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	if err := h.authUseCase.DisableMFA(c.Context(), utils.ParseUUID(userID), req.Password); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "MFA disabled successfully", nil)
}

// VerifyMFA
// @Summary Verify Multi-Factor Authentication (MFA)
// @Description Verifies MFA code for the logged-in user
// @Tags MFA
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body input.VerifyMFARequest true "Verify MFA Request"
// @Success 200 {object} utils.APIResponse{data=object} "MFA verified successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body or validation error"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized or invalid MFA code"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/mfa/verify [post]
func (h *AuthHandler) VerifyMFA(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req input.VerifyMFARequest
	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	if err := h.authUseCase.VerifyMFA(c.Context(), utils.ParseUUID(userID), &req); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "MFA verified successfully", nil)
}

// GetMe
// @Summary Get current user information
// @Description Retrieves detailed information about the currently authenticated user
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.APIResponse{data=object} "User retrieved successfully"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 404 {object} utils.APIResponse{error=utils.APIError} "User not found"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /auth/me [get]
func (h *AuthHandler) GetMe(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	user, err := h.userUseCase.GetUser(c.Context(), utils.ParseUUID(userID))
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "User retrieved successfully", user)
}
