package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"image/png"
)

// GenerateQRCode generates QR code as base64 data URL
func GenerateQRCode(content string, size int) (string, error) {
	// Generate QR code
	qr, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("failed to create QR code: %w", err)
	}

	// Create PNG image
	img := qr.Image(size)

	// Convert to base64
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", fmt.Errorf("failed to encode PNG: %w", err)
	}

	// Create data URL
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	dataURL := "data:image/png;base64," + encoded

	return dataURL, nil
}

// ValidateTOTP validates TOTP code
func ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}
