package services

import (
	"crypto/rand"
	_ "encoding/base32"
	"fmt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"math/big"
	"ms-auth/pkg/utils"
	"strings"
	_ "time"
)

// OTPService defines OTP service interface
type OTPService interface {
	GenerateSecret(accountName, issuer string) (string, error)
	GenerateQRCode(secret, accountName, issuer string) (string, error)
	ValidateCode(secret, code string) bool
	GenerateBackupCodes(count int) []string
	ValidateBackupCode(codes []string, code string) ([]string, bool)
	GenerateNumericCode(length int) string
}

// TOTPService implements TOTP-based OTP service
type TOTPService struct {
	issuer string
}

// NewTOTPService creates new TOTP service
func NewTOTPService(issuer string) *TOTPService {
	return &TOTPService{
		issuer: issuer,
	}
}

// GenerateSecret generates TOTP secret
func (s *TOTPService) GenerateSecret(accountName, issuer string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	return key.Secret(), nil
}

// GenerateQRCode generates QR code URL for TOTP setup
func (s *TOTPService) GenerateQRCode(secret, accountName, issuer string) (string, error) {
	key, err := otp.NewKeyFromURL(fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, accountName, secret, issuer,
	))
	if err != nil {
		return "", fmt.Errorf("failed to create OTP key: %w", err)
	}

	// Generate QR code as base64 data URL
	qrCode, err := utils.GenerateQRCode(key.String(), 256)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	return qrCode, nil
}

// ValidateCode validates TOTP code
func (s *TOTPService) ValidateCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes generates backup codes
func (s *TOTPService) GenerateBackupCodes(count int) []string {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		// Generate 8-character backup code
		codes[i] = s.generateBackupCode()
	}
	return codes
}

// ValidateBackupCode validates backup code and removes it from the list
func (s *TOTPService) ValidateBackupCode(codes []string, code string) ([]string, bool) {
	code = strings.ToUpper(strings.TrimSpace(code))

	for i, backupCode := range codes {
		if strings.ToUpper(backupCode) == code {
			// Remove used backup code
			newCodes := make([]string, 0, len(codes)-1)
			newCodes = append(newCodes, codes[:i]...)
			newCodes = append(newCodes, codes[i+1:]...)
			return newCodes, true
		}
	}

	return codes, false
}

// GenerateNumericCode generates numeric verification code
func (s *TOTPService) GenerateNumericCode(length int) string {
	const digits = "0123456789"
	code := make([]byte, length)

	for i := range code {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		code[i] = digits[num.Int64()]
	}

	return string(code)
}

// generateBackupCode generates single backup code
func (s *TOTPService) generateBackupCode() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 8

	code := make([]byte, length)
	for i := range code {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		code[i] = charset[num.Int64()]
	}

	// Format as XXXX-XXXX
	result := string(code)
	return result[:4] + "-" + result[4:]
}
