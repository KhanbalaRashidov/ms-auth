package handlers

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"ms-auth/internal/core/domain/entities" // Make sure entities.User and entities.UserSession are defined and tagged
	"ms-auth/internal/core/ports/input"
	"ms-auth/pkg/utils" // Assuming utils.SuccessResponse, utils.ErrorResponse, utils.ValidationErrorResponse are defined and tagged
	"net/http"
	"strconv"
)

// UserHandler handles user management requests
type UserHandler struct {
	userUseCase      input.UserUseCase
	blacklistUseCase input.BlacklistUseCase
	validator        *validator.Validate
}

// UpdateProfileRequest represents the request body for updating user profile
type UpdateProfileRequest struct {
	FirstName string                 `json:"first_name,omitempty" validate:"omitempty,max=50" example:"John"`
	LastName  string                 `json:"last_name,omitempty" validate:"omitempty,max=50" example:"Doe"`
	Avatar    string                 `json:"avatar,omitempty" validate:"omitempty,url" example:"http://example.com/avatar.jpg"`
	Metadata  map[string]interface{} `json:"metadata,omitempty" swaggertype:"object,string" example:"{\"favorite_color\": \"blue\"}"`
}

// VerifyEmailRequest represents the request body for verifying email
type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required" example:"some-verification-token"`
}

// VerifyPhoneRequest represents the request body for verifying phone
type VerifyPhoneRequest struct {
	Code string `json:"code" validate:"required,len=6,numeric" example:"123456"`
}

// UpdateUserStatusRequest represents the request body for updating user status
type UpdateUserStatusRequest struct {
	Status entities.UserStatus `json:"status" validate:"required,min=1,max=5" example:"2" enums:"1,2,3,4,5"` // Assuming UserStatus is int
	Reason string              `json:"reason,omitempty" validate:"omitempty,max=255" example:"Violated terms of service"`
}

// UpdateUserParamsRequest represents the request body for updating user parameters
type UpdateUserParamsRequest struct {
	RoleID  *string `json:"role_id,omitempty" format:"uuid" example:"a1b2c3d4-e5f6-7890-1234-567890abcdef"`
	GroupID *string `json:"group_id,omitempty" format:"uuid" example:"b2c3d4e5-f6a7-8901-2345-67890abcdef0"`
}

// AddToBlacklistRequest represents the request body for adding to blacklist
type AddToBlacklistRequest struct {
	Type   entities.BlacklistType `json:"type" validate:"required" example:"email" enums:"ip,email,username"`
	Value  string                 `json:"value" validate:"required,max=255" example:"baduser@example.com"`
	Reason string                 `json:"reason,omitempty" validate:"omitempty,max=500" example:"Spamming activity"`
}

// NewUserHandler creates new user handler
func NewUserHandler(userUseCase input.UserUseCase, blacklistUseCase input.BlacklistUseCase) *UserHandler {
	return &UserHandler{
		userUseCase:      userUseCase,
		blacklistUseCase: blacklistUseCase,
		validator:        validator.New(),
	}
}

// GetProfile
// @Summary Get current user profile
// @Description Retrieves the detailed profile information of the currently authenticated user.
// @Tags User Profile
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.APIResponse{data=object} "Profile retrieved successfully"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 404 {object} utils.APIResponse{error=utils.APIError} "User not found"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /users/profile [get]
func (h *UserHandler) GetProfile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	user, err := h.userUseCase.GetUser(c.Context(), utils.ParseUUID(userID))
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Profile retrieved successfully", user)
}

// UpdateProfile
// @Summary Update user profile
// @Description Updates the profile information of the currently authenticated user.
// @Tags User Profile
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateProfileRequest true "Update Profile Request"
// @Success 200 {object} utils.APIResponse{data=object} "Profile updated successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body or validation error"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /users/profile [put]
func (h *UserHandler) UpdateProfile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req UpdateProfileRequest

	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	// Convert to updates map
	updates := make(map[string]interface{})
	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}
	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}
	if req.Avatar != "" {
		updates["avatar"] = req.Avatar
	}
	if req.Metadata != nil {
		updates["metadata"] = req.Metadata
	}

	if err := h.userUseCase.UpdateProfile(c.Context(), utils.ParseUUID(userID), updates); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Profile updated successfully", nil)
}

// GetSessions
// @Summary Get user active sessions
// @Description Retrieves a list of all active sessions for the currently authenticated user.
// @Tags User Sessions
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.APIResponse{data=[]object} "Sessions retrieved successfully"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /users/sessions [get]
func (h *UserHandler) GetSessions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	sessions, err := h.userUseCase.GetUserSessions(c.Context(), utils.ParseUUID(userID))
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Sessions retrieved successfully", sessions)
}

// RevokeSession
// @Summary Revoke a specific user session
// @Description Revokes a single active session identified by its ID for the current user.
// @Tags User Sessions
// @Produce json
// @Security BearerAuth
// @Param session_id path string true "Session ID" format:"uuid"
// @Success 200 {object} utils.APIResponse{data=object} "Session revoked successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid session ID"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 404 {object} utils.APIResponse{error=utils.APIError} "Session not found"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /users/sessions/{session_id} [delete]
func (h *UserHandler) RevokeSession(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	sessionID := c.Params("session_id")

	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid session ID", err)
	}

	if err := h.userUseCase.RevokeSession(c.Context(), utils.ParseUUID(userID), sessionUUID); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Session revoked successfully", nil)
}

// RevokeAllSessions
// @Summary Revoke all user sessions
// @Description Revokes all active sessions for the currently authenticated user, forcing re-login on other devices.
// @Tags User Sessions
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.APIResponse{data=object} "All sessions revoked successfully"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /users/sessions/revoke-all [post]
func (h *UserHandler) RevokeAllSessions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	if err := h.userUseCase.RevokeAllSessions(c.Context(), utils.ParseUUID(userID)); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "All sessions revoked successfully", nil)
}

// SendEmailVerification
// @Summary Send email verification
// @Description Sends a new email verification link to the user's registered email address.
// @Tags User Verification
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.APIResponse{data=object} "Email verification sent successfully"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 409 {object} utils.APIResponse{error=utils.APIError} "Email already verified or too many requests"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /users/verify-email [post]
func (h *UserHandler) SendEmailVerification(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	if err := h.userUseCase.SendEmailVerification(c.Context(), utils.ParseUUID(userID)); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Email verification sent successfully", nil)
}

// VerifyEmail
// @Summary Verify email with token
// @Description Verifies the user's email address using a provided verification token.
// @Tags User Verification
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body VerifyEmailRequest true "Verify Email Request"
// @Success 200 {object} utils.APIResponse{data=object} "Email verified successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body, validation error, or invalid/expired token"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /users/verify-email/confirm [post]
func (h *UserHandler) VerifyEmail(c *fiber.Ctx) error {
	var req VerifyEmailRequest

	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	if err := h.userUseCase.VerifyEmail(c.Context(), req.Token); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Email verified successfully", nil)
}

// SendPhoneVerification
// @Summary Send phone verification code
// @Description Sends a verification code to the user's registered phone number.
// @Tags User Verification
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.APIResponse{data=object} "Phone verification code sent successfully"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 409 {object} utils.APIResponse{error=utils.APIError} "Phone already verified or too many requests"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /users/verify-phone [post]
func (h *UserHandler) SendPhoneVerification(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	if err := h.userUseCase.SendPhoneVerification(c.Context(), utils.ParseUUID(userID)); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Phone verification code sent successfully", nil)
}

// VerifyPhone
// @Summary Verify phone with code
// @Description Verifies the user's phone number using a provided verification code.
// @Tags User Verification
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body VerifyPhoneRequest true "Verify Phone Request"
// @Success 200 {object} utils.APIResponse{data=object} "Phone verified successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body, validation error, or invalid/expired code"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /users/verify-phone/confirm [post]
func (h *UserHandler) VerifyPhone(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req VerifyPhoneRequest

	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	if err := h.userUseCase.VerifyPhone(c.Context(), utils.ParseUUID(userID), req.Code); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Phone verified successfully", nil)
}

// Admin endpoints

// ListUsers
// @Summary List users (Admin Only)
// @Description Retrieves a paginated list of all registered users. This endpoint is for administrators only.
// @Tags Admin - User Management
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Number of users to return (max 100)" default(20) minimum(1) maximum(100)
// @Param offset query int false "Offset for pagination" default(0) minimum(0)
// @Success 200 {object} utils.APIResponse{data=[]object} "Users retrieved successfully"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized - Admin privilege required"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /admin/users [get]
func (h *UserHandler) ListUsers(c *fiber.Ctx) error {
	// Get pagination parameters
	//offset, _ := strconv.Atoi(c.Query("offset", "0"))
	limit, _ := strconv.Atoi(c.Query("limit", "20"))

	// Limit max results
	if limit > 100 {
		limit = 100
	}

	// TODO: Implement list users functionality in UserUseCase
	// For now, return "Not implemented"
	// users, err := h.userUseCase.ListUsers(c.Context(), offset, limit)
	// if err != nil {
	//    return utils.HandleServiceError(c, err)
	// }
	// return utils.SuccessResponse(c, http.StatusOK, "Users retrieved successfully", users)

	return utils.ErrorResponse(c, http.StatusNotImplemented, "Not implemented yet", nil)
}

// GetUser
// @Summary Get user by ID (Admin Only)
// @Description Retrieves detailed information about a specific user by their ID. This endpoint is for administrators only.
// @Tags Admin - User Management
// @Produce json
// @Security BearerAuth
// @Param user_id path string true "User ID" format:"uuid"
// @Success 200 {object} utils.APIResponse{data=object} "User retrieved successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid user ID"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized - Admin privilege required"
// @Failure 404 {object} utils.APIResponse{error=utils.APIError} "User not found"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /admin/users/{user_id} [get]
func (h *UserHandler) GetUser(c *fiber.Ctx) error {
	userID := c.Params("user_id")

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID", err)
	}

	user, err := h.userUseCase.GetUser(c.Context(), userUUID)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "User retrieved successfully", user)
}

// UpdateUserStatus
// @Summary Update user status (Admin Only)
// @Description Updates the status of a user (e.g., active, suspended, locked). This endpoint is for administrators only.
// @Tags Admin - User Management
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param user_id path string true "User ID" format:"uuid"
// @Param request body UpdateUserStatusRequest true "Update User Status Request"
// @Success 200 {object} utils.APIResponse{data=object} "User status updated successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body, validation error, or invalid user ID"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized - Admin privilege required"
// @Failure 404 {object} utils.APIResponse{error=utils.APIError} "User not found"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /admin/users/{user_id}/status [put]
func (h *UserHandler) UpdateUserStatus(c *fiber.Ctx) error {
	userID := c.Params("user_id")

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID", err)
	}

	var req UpdateUserStatusRequest

	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	updateReq := &input.UpdateUserStatusRequest{
		UserID: userUUID,
		Status: req.Status,
		Reason: req.Reason,
	}

	if err := h.userUseCase.UpdateUserStatus(c.Context(), updateReq); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "User status updated successfully", nil)
}

// UpdateUserParams
// @Summary Update user role and group (Admin Only)
// @Description Updates the role and/or group of a specific user. This endpoint is for administrators only.
// @Tags Admin - User Management
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param user_id path string true "User ID" format:"uuid"
// @Param request body UpdateUserParamsRequest true "Update User Parameters Request"
// @Success 200 {object} utils.APIResponse{data=object} "User parameters updated successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body, validation error, or invalid ID"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized - Admin privilege required"
// @Failure 404 {object} utils.APIResponse{error=utils.APIError} "User not found"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /admin/users/{user_id}/params [put]
func (h *UserHandler) UpdateUserParams(c *fiber.Ctx) error {
	userID := c.Params("user_id")

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID", err)
	}

	var req UpdateUserParamsRequest

	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}
	// No h.validator.Struct(&req) here because both fields are omitempty and pointers.
	// Validation for UUID format is handled manually below.

	updateReq := &input.UpdateUserParamsRequest{
		UserID: userUUID,
	}

	if req.RoleID != nil {
		roleUUID, err := uuid.Parse(*req.RoleID)
		if err != nil {
			return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid role ID", err)
		}
		updateReq.RoleID = &roleUUID
	}

	if req.GroupID != nil {
		groupUUID, err := uuid.Parse(*req.GroupID)
		if err != nil {
			return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid group ID", err)
		}
		updateReq.GroupID = &groupUUID
	}

	if err := h.userUseCase.UpdateUserParams(c.Context(), updateReq); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "User parameters updated successfully", nil)
}

// DeleteUser
// @Summary Delete user (Admin Only)
// @Description Deletes a user, either soft (default) or hard. This endpoint is for administrators only.
// @Tags Admin - User Management
// @Produce json
// @Security BearerAuth
// @Param user_id path string true "User ID" format:"uuid"
// @Param hard query boolean false "Perform a hard delete instead of soft delete" default(false)
// @Success 200 {object} utils.APIResponse{data=object} "User deleted successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid user ID"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized - Admin privilege required"
// @Failure 404 {object} utils.APIResponse{error=utils.APIError} "User not found"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /admin/users/{user_id} [delete]
func (h *UserHandler) DeleteUser(c *fiber.Ctx) error {
	userID := c.Params("user_id")

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID", err)
	}

	// Check if it should be soft delete (default) or hard delete
	hardDelete := c.QueryBool("hard", false)

	if err := h.userUseCase.DeleteUser(c.Context(), userUUID, !hardDelete); err != nil {
		return utils.HandleServiceError(c, err)
	}

	deleteType := "soft"
	if hardDelete {
		deleteType = "hard"
	}

	return utils.SuccessResponse(c, http.StatusOK, "User "+deleteType+" deleted successfully", nil)
}

// Blacklist management endpoints

// GetBlacklist
// @Summary Get blacklist entries (Admin Only)
// @Description Retrieves a paginated list of blacklist entries, optionally filtered by type. This endpoint is for administrators only.
// @Tags Admin - Blacklist Management
// @Produce json
// @Security BearerAuth
// @Param type query string false "Type of blacklist entry (e.g., ip, email, username)" Enums(ip,email,username)
// @Param limit query int false "Number of entries to return (max 100)" default(20) minimum(1) maximum(100)
// @Param offset query int false "Offset for pagination" default(0) minimum(0)
// @Success 200 {object} utils.APIResponse{data=[]object} "Blacklist retrieved successfully"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized - Admin privilege required"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /admin/blacklist [get]
func (h *UserHandler) GetBlacklist(c *fiber.Ctx) error {
	blacklistType := c.Query("type", "")
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	limit, _ := strconv.Atoi(c.Query("limit", "20"))

	// Limit max results
	if limit > 100 {
		limit = 100
	}

	var bType entities.BlacklistType
	if blacklistType != "" {
		bType = entities.BlacklistType(blacklistType)
	}

	blacklists, err := h.blacklistUseCase.GetBlacklist(c.Context(), bType, offset, limit)
	if err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Blacklist retrieved successfully", blacklists)
}

// AddToBlacklist
// @Summary Add entry to blacklist (Admin Only)
// @Description Adds an IP, email, or username to the blacklist to prevent future access. This endpoint is for administrators only.
// @Tags Admin - Blacklist Management
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body AddToBlacklistRequest true "Add To Blacklist Request"
// @Success 201 {object} utils.APIResponse{data=object} "Added to blacklist successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid request body, validation error, or duplicate entry"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized - Admin privilege required"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /admin/blacklist [post]
func (h *UserHandler) AddToBlacklist(c *fiber.Ctx) error {
	var req AddToBlacklistRequest

	if err := c.BodyParser(&req); err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	if err := h.validator.Struct(&req); err != nil {
		return utils.ValidationErrorResponse(c, err)
	}

	if err := h.blacklistUseCase.AddToBlacklist(c.Context(), req.Type, req.Value, req.Reason); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusCreated, "Added to blacklist successfully", nil)
}

// RemoveFromBlacklist
// @Summary Remove entry from blacklist (Admin Only)
// @Description Removes an entry from the blacklist by its ID. This endpoint is for administrators only.
// @Tags Admin - Blacklist Management
// @Produce json
// @Security BearerAuth
// @Param blacklist_id path string true "Blacklist Entry ID" format:"uuid"
// @Success 200 {object} utils.APIResponse{data=object} "Removed from blacklist successfully"
// @Failure 400 {object} utils.APIResponse{error=utils.APIError} "Invalid blacklist ID"
// @Failure 401 {object} utils.APIResponse{error=utils.APIError} "Unauthorized - Admin privilege required"
// @Failure 404 {object} utils.APIResponse{error=utils.APIError} "Blacklist entry not found"
// @Failure 500 {object} utils.APIResponse{error=utils.APIError} "Internal server error"
// @Router /admin/blacklist/{blacklist_id} [delete]
func (h *UserHandler) RemoveFromBlacklist(c *fiber.Ctx) error {
	blacklistID := c.Params("blacklist_id")

	blacklistUUID, err := uuid.Parse(blacklistID)
	if err != nil {
		return utils.ErrorResponse(c, http.StatusBadRequest, "Invalid blacklist ID", err)
	}

	if err := h.blacklistUseCase.RemoveFromBlacklist(c.Context(), blacklistUUID); err != nil {
		return utils.HandleServiceError(c, err)
	}

	return utils.SuccessResponse(c, http.StatusOK, "Removed from blacklist successfully", nil)
}
