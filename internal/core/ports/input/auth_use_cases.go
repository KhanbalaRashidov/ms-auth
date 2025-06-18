package input

import (
	"context"
	"github.com/google/uuid"
	"ms-auth/internal/core/domain/entities"
)

// RegisterRequest represents user registration request
type RegisterRequest struct {
	Username  string `json:"username" validate:"required,min=3,max=50,alphanum"`
	Email     string `json:"email" validate:"required,email"`
	Phone     string `json:"phone,omitempty" validate:"omitempty,e164"`
	Password  string `json:"password" validate:"required,min=8,max=128"`
	FirstName string `json:"first_name,omitempty" validate:"omitempty,max=50"`
	LastName  string `json:"last_name,omitempty" validate:"omitempty,max=50"`
}

// LoginRequest represents user login request
type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required"` // username, email, phone or id
	Password   string `json:"password" validate:"required"`
	DeviceID   string `json:"device_id,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	Remember   bool   `json:"remember"`
}

// LoginResponse represents login response
type LoginResponse struct {
	User         *entities.User      `json:"user"`
	TokenPair    *entities.TokenPair `json:"tokens"`
	RequiresMFA  bool                `json:"requires_mfa"`
	MFAChallenge string              `json:"mfa_challenge,omitempty"`
}

// RefreshTokenRequest represents refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
	DeviceID     string `json:"device_id,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
}

// ChangePasswordRequest represents change password request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
}

// ForgotPasswordRequest represents forgot password request
type ForgotPasswordRequest struct {
	Identifier string `json:"identifier" validate:"required"` // email, phone or username
}

// ResetPasswordRequest represents reset password request
type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
}

// UpdateUserStatusRequest represents update user status request
type UpdateUserStatusRequest struct {
	UserID uuid.UUID           `json:"user_id" validate:"required"`
	Status entities.UserStatus `json:"status" validate:"required"`
	Reason string              `json:"reason,omitempty"`
}

// UpdateUserParamsRequest represents update user params request
type UpdateUserParamsRequest struct {
	UserID  uuid.UUID  `json:"user_id" validate:"required"`
	RoleID  *uuid.UUID `json:"role_id,omitempty"`
	GroupID *uuid.UUID `json:"group_id,omitempty"`
}

// EnableMFARequest represents enable MFA request
type EnableMFARequest struct {
	Password string `json:"password" validate:"required"`
}

// EnableMFAResponse represents enable MFA response
type EnableMFAResponse struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

// VerifyMFARequest represents verify MFA request
type VerifyMFARequest struct {
	Code string `json:"code" validate:"required,len=6,numeric"`
}

// LogoutRequest represents logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	LogoutAll    bool   `json:"logout_all"`
}

// AuthUseCase defines authentication use cases
type AuthUseCase interface {
	// Authentication
	Register(ctx context.Context, req *RegisterRequest) (*entities.User, error)
	Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error)
	Logout(ctx context.Context, userID uuid.UUID, req *LogoutRequest) error
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*entities.TokenPair, error)

	// Password Management
	ChangePassword(ctx context.Context, userID uuid.UUID, req *ChangePasswordRequest) error
	ForgotPassword(ctx context.Context, req *ForgotPasswordRequest) error
	ResetPassword(ctx context.Context, req *ResetPasswordRequest) error

	// Token Management
	ValidateToken(ctx context.Context, tokenString string, tokenType entities.TokenType) (*entities.JWTClaims, error)
	RevokeToken(ctx context.Context, tokenID uuid.UUID) error
	RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error

	// Multi-Factor Authentication
	EnableMFA(ctx context.Context, userID uuid.UUID, req *EnableMFARequest) (*EnableMFAResponse, error)
	DisableMFA(ctx context.Context, userID uuid.UUID, password string) error
	VerifyMFA(ctx context.Context, userID uuid.UUID, req *VerifyMFARequest) error
	GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error)
}

// UserUseCase defines user management use cases
type UserUseCase interface {
	// User Management
	GetUser(ctx context.Context, userID uuid.UUID) (*entities.User, error)
	GetUserByIdentifier(ctx context.Context, identifier string) (*entities.User, error)
	UpdateUserStatus(ctx context.Context, req *UpdateUserStatusRequest) error
	UpdateUserParams(ctx context.Context, req *UpdateUserParamsRequest) error
	DeleteUser(ctx context.Context, userID uuid.UUID, soft bool) error

	// User Profile
	UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error

	// Verification
	SendEmailVerification(ctx context.Context, userID uuid.UUID) error
	VerifyEmail(ctx context.Context, token string) error
	SendPhoneVerification(ctx context.Context, userID uuid.UUID) error
	VerifyPhone(ctx context.Context, userID uuid.UUID, code string) error

	// User Sessions
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*entities.Token, error)
	RevokeSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error
	RevokeAllSessions(ctx context.Context, userID uuid.UUID) error
}

// BlacklistUseCase defines blacklist management use cases
type BlacklistUseCase interface {
	// Blacklist Check
	IsBlacklisted(ctx context.Context, blacklistType entities.BlacklistType, value string) (bool, error)
	CheckMultiple(ctx context.Context, checks map[entities.BlacklistType]string) (map[string]bool, error)

	// Blacklist Management
	AddToBlacklist(ctx context.Context, blacklistType entities.BlacklistType, value, reason string) error
	RemoveFromBlacklist(ctx context.Context, id uuid.UUID) error
	GetBlacklist(ctx context.Context, blacklistType entities.BlacklistType, offset, limit int) ([]*entities.Blacklist, error)
}
