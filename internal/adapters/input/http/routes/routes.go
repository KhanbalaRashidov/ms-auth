package routes

import (
	"context"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"gorm.io/gorm" // Import gorm.DB for type hinting the database connection

	"ms-auth/internal/adapters/input/http/handlers"
	"ms-auth/internal/adapters/input/http/middleware"
	"ms-auth/internal/adapters/output/persistence/postgres"
	"ms-auth/internal/config"
	"ms-auth/internal/core/domain/entities"
	"ms-auth/internal/core/domain/services"
	"ms-auth/internal/core/ports/input"
	"ms-auth/internal/core/ports/output"
)

// BootstrapApp initializes and sets up all application dependencies (DB, Repos, Services, UseCases)
// and registers the API routes. It also starts background tasks.
// It returns the GORM database connection and a function to clean it up,
// allowing `main` to manage the deferred database closure.
func BootstrapApp(app *fiber.App, cfg *config.Config) (*gorm.DB, func()) {
	// --- Database Initialization ---
	// Connect to the PostgreSQL database
	db, err := config.InitDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Run database migrations to ensure schema is up-to-date
	if err := config.AutoMigrate(db); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// --- Repository Initialization ---
	// Create instances of repository implementations using the database connection
	userRepo := postgres.NewUserRepository(db)
	tokenRepo := postgres.NewTokenRepository(db)
	blacklistRepo := postgres.NewBlacklistRepository(db)
	passwordHistoryRepo := postgres.NewPasswordHistoryRepository(db)

	// --- Service Initialization ---
	// Create instances of core domain services
	tokenService := services.NewJWTTokenService(
		cfg.JWT.SecretKey,
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
	)
	passwordService := services.NewBCryptPasswordService(cfg.Password.Complexity)
	otpService := services.NewTOTPService(cfg.JWT.Issuer)

	// --- Use Case (Application Layer) Initialization ---
	// Create instances of use cases, injecting the necessary services and repositories
	authUseCase := services.NewAuthService(
		userRepo,
		tokenRepo,
		blacklistRepo,
		passwordHistoryRepo,
		tokenService,
		passwordService,
		otpService,
	)
	userUseCase := services.NewUserService(userRepo, tokenRepo)
	blacklistUseCase := services.NewBlacklistService(blacklistRepo)

	// --- Middleware Setup ---
	// Apply global Fiber middleware
	setupMiddleware(app, cfg)

	// --- Route Setup ---
	// Register all API endpoints
	SetupRoutes(app, cfg, authUseCase, userUseCase, blacklistUseCase)

	// --- Background Tasks ---
	// Start periodic cleanup tasks in a separate goroutine
	go startBackgroundTasks(cfg, tokenRepo, blacklistRepo, passwordHistoryRepo)

	// Return the database connection and a cleanup function
	// The cleanup function will be deferred in `main` to ensure proper resource release.
	return db, func() {
		config.CloseDatabase(db)
	}
}

// SetupRoutes configures all API endpoints for the application.
func SetupRoutes(
	app *fiber.App,
	config *config.Config,
	authUseCase input.AuthUseCase,
	userUseCase input.UserUseCase,
	blacklistUseCase input.BlacklistUseCase,
) {
	// Initialize HTTP handlers with their respective use cases
	authHandler := handlers.NewAuthHandler(authUseCase, userUseCase)
	userHandler := handlers.NewUserHandler(userUseCase, blacklistUseCase)

	// Create an API group for version 1 routes (/api/v1)
	api := app.Group("/api")

	// --- API Version Specific Health Check ---
	// This is an additional health check endpoint specific to the API version.
	api.Get("/actuator/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":  "ok",
			"service": "ms-auth",
			"version": "v1", // Indicate the API version
		})
	})

	// --- Public Authentication Routes (no authentication required) ---
	auth := api.Group("/auth")
	{
		auth.Post("/register", authHandler.Register)
		auth.Post("/login", authHandler.Login)
		auth.Post("/refresh", authHandler.RefreshToken)
		auth.Post("/forgot-password", authHandler.ForgotPassword)
		auth.Post("/reset-password", authHandler.ResetPassword)
		auth.Post("/mfa/verify", middleware.MFAAuthMiddleware(authUseCase), authHandler.VerifyMFA)
	}

	// --- Protected Authentication Routes (authentication required) ---
	protected := api.Group("/auth")
	protected.Use(middleware.AuthMiddleware(authUseCase)) // Apply authentication middleware
	{
		protected.Post("/logout", authHandler.Logout)
		protected.Post("/change-password", authHandler.ChangePassword)
		protected.Get("/me", authHandler.GetMe)

		// Multi-Factor Authentication (MFA) routes within the protected group
		mfa := protected.Group("/mfa")
		{
			mfa.Post("/enable", authHandler.EnableMFA)
			mfa.Post("/disable", authHandler.DisableMFA)
		}
	}

	// --- User Management Routes (authentication required) ---
	users := api.Group("/users")
	users.Use(middleware.AuthMiddleware(authUseCase)) // Apply authentication middleware
	{
		users.Get("/profile", userHandler.GetProfile)
		users.Put("/profile", userHandler.UpdateProfile)
		users.Get("/sessions", userHandler.GetSessions)
		users.Delete("/sessions/:session_id", userHandler.RevokeSession)
		users.Delete("/sessions", userHandler.RevokeAllSessions)

		// Email verification routes
		users.Post("/verify-email", userHandler.SendEmailVerification)
		users.Post("/verify-email/confirm", userHandler.VerifyEmail)

		// Phone verification routes
		users.Post("/verify-phone", userHandler.SendPhoneVerification)
		users.Post("/verify-phone/confirm", userHandler.VerifyPhone)
	}

	// --- Admin Routes (require admin privileges) ---
	admin := api.Group("/admin")
	admin.Use(middleware.AuthMiddleware(authUseCase)) // Require authentication
	admin.Use(middleware.RequireRole("admin"))        // Placeholder for role-based access control
	{
		// Admin user management routes
		adminUsers := admin.Group("/users")
		{
			adminUsers.Get("/", userHandler.ListUsers)
			adminUsers.Get("/:user_id", userHandler.GetUser)
			adminUsers.Put("/:user_id/status", userHandler.UpdateUserStatus)
			adminUsers.Put("/:user_id/params", userHandler.UpdateUserParams)
			adminUsers.Delete("/:user_id", userHandler.DeleteUser)
		}

		// Admin blacklist management routes
		blacklist := admin.Group("/blacklist")
		{
			blacklist.Get("/", userHandler.GetBlacklist)
			blacklist.Post("/", userHandler.AddToBlacklist)
			blacklist.Delete("/:blacklist_id", userHandler.RemoveFromBlacklist)
		}
	}

	// --- Internal Token Validation Endpoint (for other microservices) ---
	api.Post("/validate-token", func(c *fiber.Ctx) error {
		var req struct {
			Token string `json:"token" validate:"required"`
		}

		// Parse request body for the token
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"valid": false,
				"error": "Invalid request body",
			})
		}

		// Validate the token using the authentication use case
		claims, err := authUseCase.ValidateToken(c.Context(), req.Token, entities.TokenTypeAccess)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{ // Return 401 for invalid tokens
				"valid": false,
				"error": err.Error(),
			})
		}

		// Return valid status and claims if token is valid
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"valid":  true,
			"claims": claims,
		})
	})
}

// setupMiddleware configures and applies global Fiber middleware to the application.
func setupMiddleware(app *fiber.App, cfg *config.Config) {
	// Recovery middleware to gracefully recover from panics and prevent server crashes
	app.Use(recover.New())

	// Logger middleware for request logging in development environments
	if cfg.IsDevelopment() {
		app.Use(logger.New(logger.Config{
			Format: "[${time}] ${status} - ${method} ${path} - ${latency}\n",
		}))
	}

	// CORS middleware configuration for Cross-Origin Resource Sharing
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
	}))

	// IP-based rate limiting middleware if enabled in configuration
	if cfg.RateLimit.RequestsPerMinute > 0 {
		app.Use(middleware.IPBasedRateLimiter(cfg.RateLimit.RequestsPerMinute, 10)) // Default window of 10 seconds
	}

	// Specific rate limiters for sensitive authentication endpoints (login, register)
	app.Use(middleware.LoginRateLimiter(
		cfg.RateLimit.LoginAttempts,
		cfg.RateLimit.LoginWindow,
	))

	app.Use(middleware.RegisterRateLimiter(
		cfg.RateLimit.RegisterAttempts,
		cfg.RateLimit.RegisterWindow,
	))
}

// startBackgroundTasks runs periodic cleanup routines for expired tokens, blacklists,
// and old password history entries. This function runs in a separate goroutine.
func startBackgroundTasks(
	cfg *config.Config,
	tokenRepo output.TokenRepository,
	blacklistRepo output.BlacklistRepository,
	passwordHistoryRepo output.PasswordHistoryRepository,
) {
	// Ticker for cleaning up expired tokens (runs every hour)
	tokenCleanupTicker := time.NewTicker(time.Hour)
	defer tokenCleanupTicker.Stop() // Ensure ticker is stopped when the function exits

	// Ticker for cleaning up expired blacklists. Its interval is configurable
	// and it only runs if `AutoCleanup` is enabled in the blacklist configuration.
	var blacklistCleanupTicker *time.Ticker
	if cfg.Blacklist.AutoCleanup {
		blacklistCleanupTicker = time.NewTicker(cfg.Blacklist.CleanupInterval)
		defer blacklistCleanupTicker.Stop() // Ensure ticker is stopped
	}

	// Ticker for cleaning up old password history entries (runs every 24 hours)
	passwordCleanupTicker := time.NewTicker(24 * time.Hour)
	defer passwordCleanupTicker.Stop() // Ensure ticker is stopped

	ctx := context.Background() // Use a background context for long-running, non-request-specific tasks

	// Infinite loop to listen for events from the tickers
	for {
		select {
		case <-tokenCleanupTicker.C:
			// Execute token cleanup
			log.Println("🧹 Cleaning up expired tokens...")
			if err := tokenRepo.CleanupExpiredTokens(ctx); err != nil {
				log.Printf("Error cleaning up tokens: %v", err)
			}

		case <-blacklistCleanupTicker.C:
			// Execute blacklist cleanup only if auto-cleanup is enabled
			if cfg.Blacklist.AutoCleanup {
				log.Println("🧹 Cleaning up expired blacklists...")
				if err := blacklistRepo.CleanupExpired(ctx); err != nil {
					log.Printf("Error cleaning up blacklists: %v", err)
				}
			}

		case <-passwordCleanupTicker.C:
			// Execute password history cleanup
			log.Println("🧹 Cleaning up old passwords...")
			// Calculate the maximum age for passwords based on configuration
			maxAge := time.Duration(cfg.Password.Complexity.MaxAge) * 24 * time.Hour
			if err := passwordHistoryRepo.CleanupExpiredPasswords(ctx, maxAge); err != nil {
				log.Printf("Error cleaning up password history: %v", err)
			}
		}
	}
}
