package config

import (
	"github.com/joho/godotenv"
	"ms-auth/internal/core/domain/entities"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds application configuration
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	JWT       JWTConfig
	Password  PasswordConfig
	Redis     RedisConfig
	Email     EmailConfig
	SMS       SMSConfig
	RateLimit RateLimitConfig
	Blacklist BlacklistConfig
	Security  SecurityConfig
	CORS      CORSConfig
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host         string
	Port         string
	Environment  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	Name            string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	SecretKey                 string
	Issuer                    string
	Audience                  string
	AccessTokenDuration       time.Duration
	RefreshTokenDuration      time.Duration
	ResetTokenDuration        time.Duration
	VerificationTokenDuration time.Duration
}

// PasswordConfig holds password configuration
type PasswordConfig struct {
	Complexity entities.PasswordComplexity
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

// EmailConfig holds email configuration
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
}

// SMSConfig holds SMS configuration
type SMSConfig struct {
	Provider  string
	APIKey    string
	APISecret string
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	LoginAttempts     int
	LoginWindow       time.Duration
	RegisterAttempts  int
	RegisterWindow    time.Duration
	RequestsPerMinute int
}

// BlacklistConfig holds blacklist configuration
type BlacklistConfig struct {
	CheckOnRegister bool
	CheckOnLogin    bool
	AutoCleanup     bool
	CleanupInterval time.Duration
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	EnableMFA           bool
	RequireEmailVerify  bool
	RequirePhoneVerify  bool
	SessionTimeout      time.Duration
	MaxSessions         int
	AllowMultipleLogins bool
	IPWhitelist         []string
	TrustedProxies      []string
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	AllowCredentials bool
	ExposeHeaders    []string
	MaxAge           time.Duration
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	_ = godotenv.Load(".env")

	return &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         getEnv("SERVER_PORT", "8080"),
			Environment:  getEnv("ENVIRONMENT", "development"),
			ReadTimeout:  getDurationEnv("READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getDurationEnv("WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getDurationEnv("IDLE_TIMEOUT", 120*time.Second),
		},
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnv("DB_PORT", "5432"),
			User:            getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASSWORD", "postgres"),
			Name:            getEnv("DB_NAME", "ms_auth"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getIntEnv("DB_MAX_OPEN_CONNS", 100),
			MaxIdleConns:    getIntEnv("DB_MAX_IDLE_CONNS", 10),
			ConnMaxLifetime: getDurationEnv("DB_CONN_MAX_LIFETIME", time.Hour),
			ConnMaxIdleTime: getDurationEnv("DB_CONN_MAX_IDLE_TIME", 10*time.Minute),
		},
		JWT: JWTConfig{
			SecretKey:                 getEnv("JWT_SECRET_KEY", "your-secret-key-change-in-production"),
			Issuer:                    getEnv("JWT_ISSUER", "ms-auth"),
			Audience:                  getEnv("JWT_AUDIENCE", "ms-auth-api"),
			AccessTokenDuration:       getDurationEnv("JWT_ACCESS_DURATION", time.Hour),
			RefreshTokenDuration:      getDurationEnv("JWT_REFRESH_DURATION", 7*24*time.Hour),
			ResetTokenDuration:        getDurationEnv("JWT_RESET_DURATION", time.Hour),
			VerificationTokenDuration: getDurationEnv("JWT_VERIFICATION_DURATION", 24*time.Hour),
		},
		Password: PasswordConfig{
			Complexity: entities.PasswordComplexity{
				MinLength:      getIntEnv("PASSWORD_MIN_LENGTH", 8),
				MaxLength:      getIntEnv("PASSWORD_MAX_LENGTH", 128),
				RequireUpper:   getBoolEnv("PASSWORD_REQUIRE_UPPER", true),
				RequireLower:   getBoolEnv("PASSWORD_REQUIRE_LOWER", true),
				RequireDigit:   getBoolEnv("PASSWORD_REQUIRE_DIGIT", true),
				RequireSpecial: getBoolEnv("PASSWORD_REQUIRE_SPECIAL", true),
				PreventReuse:   getIntEnv("PASSWORD_PREVENT_REUSE", 5),
				MaxAge:         getIntEnv("PASSWORD_MAX_AGE", 90),
			},
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnv("REDIS_PORT", "6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getIntEnv("REDIS_DB", 0),
		},
		Email: EmailConfig{
			SMTPHost:     getEnv("SMTP_HOST", "smtp.mailtrap.io"),
			SMTPPort:     getIntEnv("SMTP_PORT", 587),
			SMTPUsername: getEnv("SMTP_USERNAME", ""),
			SMTPPassword: getEnv("SMTP_PASSWORD", ""),
			FromEmail:    getEnv("FROM_EMAIL", "noreply@example.com"),
			FromName:     getEnv("FROM_NAME", "MS-Auth"),
		},
		SMS: SMSConfig{
			Provider:  getEnv("SMS_PROVIDER", ""),
			APIKey:    getEnv("SMS_API_KEY", ""),
			APISecret: getEnv("SMS_API_SECRET", ""),
		},
		RateLimit: RateLimitConfig{
			LoginAttempts:     getIntEnv("RATE_LIMIT_LOGIN_ATTEMPTS", 5),
			LoginWindow:       getDurationEnv("RATE_LIMIT_LOGIN_WINDOW", 15*time.Minute),
			RegisterAttempts:  getIntEnv("RATE_LIMIT_REGISTER_ATTEMPTS", 3),
			RegisterWindow:    getDurationEnv("RATE_LIMIT_REGISTER_WINDOW", time.Hour),
			RequestsPerMinute: getIntEnv("RATE_LIMIT_REQUESTS_PER_MINUTE", 100),
		},
		Blacklist: BlacklistConfig{
			CheckOnRegister: getBoolEnv("BLACKLIST_CHECK_ON_REGISTER", true),
			CheckOnLogin:    getBoolEnv("BLACKLIST_CHECK_ON_LOGIN", true),
			AutoCleanup:     getBoolEnv("BLACKLIST_AUTO_CLEANUP", true),
			CleanupInterval: getDurationEnv("BLACKLIST_CLEANUP_INTERVAL", 24*time.Hour),
		},
		Security: SecurityConfig{
			EnableMFA:           getBoolEnv("SECURITY_ENABLE_MFA", false),
			RequireEmailVerify:  getBoolEnv("SECURITY_REQUIRE_EMAIL_VERIFY", false),
			RequirePhoneVerify:  getBoolEnv("SECURITY_REQUIRE_PHONE_VERIFY", false),
			SessionTimeout:      getDurationEnv("SECURITY_SESSION_TIMEOUT", 24*time.Hour),
			MaxSessions:         getIntEnv("SECURITY_MAX_SESSIONS", 5),
			AllowMultipleLogins: getBoolEnv("SECURITY_ALLOW_MULTIPLE_LOGINS", true),
			IPWhitelist:         getSliceEnv("SECURITY_IP_WHITELIST", []string{}),
			TrustedProxies:      getSliceEnv("SECURITY_TRUSTED_PROXIES", []string{}),
		},
		CORS: CORSConfig{
			AllowOrigins:     getSliceEnv("CORS_ALLOW_ORIGINS", []string{"*"}),
			AllowMethods:     getSliceEnv("CORS_ALLOW_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
			AllowHeaders:     getSliceEnv("CORS_ALLOW_HEADERS", []string{"*"}),
			AllowCredentials: getBoolEnv("CORS_ALLOW_CREDENTIALS", true),
			ExposeHeaders:    getSliceEnv("CORS_EXPOSE_HEADERS", []string{}),
			MaxAge:           getDurationEnv("CORS_MAX_AGE", 12*time.Hour),
		},
	}, nil
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getSliceEnv(key string, defaultValue []string) []string {
	if value, exists := os.LookupEnv(key); exists {
		if value == "" {
			return []string{}
		}
		return strings.Split(value, ",")
	}
	return defaultValue
}

// IsDevelopment returns true if environment is development
func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}

// IsProduction returns true if environment is production
func (c *Config) IsProduction() bool {
	return c.Server.Environment == "production"
}

// GetDSN returns database connection string
func (c *Config) GetDSN() string {
	return "host=" + c.Database.Host +
		" port=" + c.Database.Port +
		" user=" + c.Database.User +
		" password=" + c.Database.Password +
		" dbname=" + c.Database.Name +
		" sslmode=" + c.Database.SSLMode
}

// GetRedisAddr returns Redis address
func (c *Config) GetRedisAddr() string {
	return c.Redis.Host + ":" + c.Redis.Port
}
