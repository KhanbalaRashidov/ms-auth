package utils

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"ms-auth/internal/core/domain/entities"
	"time"
)

// GenerateJWT generates JWT token
func GenerateJWT(claims *entities.JWTClaims, secretKey string) (string, error) {
	// Create JWT claims
	jwtClaims := jwt.MapClaims{
		"user_id":    claims.UserID.String(),
		"username":   claims.Username,
		"email":      claims.Email,
		"token_id":   claims.TokenID.String(),
		"token_type": claims.TokenType,
		"iat":        claims.IssuedAt,
		"exp":        claims.ExpiresAt,
		"nbf":        claims.NotBefore,
		"iss":        claims.Issuer,
		"aud":        claims.Audience,
	}

	// Always add the role claim, even if it's an empty string.
	// The `claims` object is a pointer, so it won't be nil if the function is called.
	// `claims.Role` is a string and always exists.
	jwtClaims["role"] = claims.Role // Dəyişiklik burada edildi.

	if claims.GroupID != nil {
		jwtClaims["group_id"] = claims.GroupID.String()
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)

	// Sign token
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateJWT validates JWT token and returns claims
func ValidateJWT(tokenString, secretKey string) (*entities.JWTClaims, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	// Validate token
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	// Parse claims
	jwtClaims, err := parseJWTClaims(claims)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().Unix() > jwtClaims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	// Check not before
	if time.Now().Unix() < jwtClaims.NotBefore {
		return nil, errors.New("token not yet valid")
	}

	return jwtClaims, nil
}

// parseJWTClaims parses JWT claims map to JWTClaims struct
func parseJWTClaims(claims jwt.MapClaims) (*entities.JWTClaims, error) {
	jwtClaims := &entities.JWTClaims{}

	// Parse user_id
	if userIDStr, ok := claims["user_id"].(string); ok {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			return nil, errors.New("invalid user_id")
		}
		jwtClaims.UserID = userID
	} else {
		return nil, errors.New("missing user_id")
	}

	// Parse token_id
	if tokenIDStr, ok := claims["token_id"].(string); ok {
		tokenID, err := uuid.Parse(tokenIDStr)
		if err != nil {
			return nil, errors.New("invalid token_id")
		}
		jwtClaims.TokenID = tokenID
	} else {
		return nil, errors.New("missing token_id")
	}

	// Parse token_type
	if tokenTypeStr, ok := claims["token_type"].(string); ok {
		jwtClaims.TokenType = entities.TokenType(tokenTypeStr)
	} else {
		return nil, errors.New("missing token_type")
	}

	// Parse optional fields
	if username, ok := claims["username"].(string); ok {
		jwtClaims.Username = username
	}

	if email, ok := claims["email"].(string); ok {
		jwtClaims.Email = email
	}

	// Parse role
	// No need for `if roleStr, ok := claims["role"].(string); ok`
	// because `claims["role"]` will always exist if added in GenerateJWT,
	// and if it's a string, the type assertion will succeed.
	// If it's not present (e.g., old token or not added), it will be default ""
	if roleStr, ok := claims["role"].(string); ok { // Still a good practice to check if it's actually a string
		jwtClaims.Role = roleStr
	}

	if groupIDStr, ok := claims["group_id"].(string); ok {
		groupID, err := uuid.Parse(groupIDStr)
		if err == nil {
			jwtClaims.GroupID = &groupID
		}
	}

	// Parse timestamps
	if iat, ok := claims["iat"].(float64); ok {
		jwtClaims.IssuedAt = int64(iat)
	}

	if exp, ok := claims["exp"].(float64); ok {
		jwtClaims.ExpiresAt = int64(exp)
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		jwtClaims.NotBefore = int64(nbf)
	}

	if iss, ok := claims["iss"].(string); ok {
		jwtClaims.Issuer = iss
	}

	if aud, ok := claims["aud"].(string); ok {
		jwtClaims.Audience = aud
	}

	return jwtClaims, nil
}
