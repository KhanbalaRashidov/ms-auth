package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"

	_ "ms-auth/docs" // Import generated Swagger documentation
	"ms-auth/internal/adapters/input/http/routes"
	"ms-auth/internal/config"
)

// @title           ms-auth API
// @version         1.0
// @description     Authentication and User Management Microservice
// @termsOfService  http://example.com/terms/
// @contact.name   Khanbala Rashidov
// @contact.email  contact@example.com
// @license.name  MIT
// @host      localhost:3000
// @BasePath  /
func main() {
	// Load application configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize Fiber application with custom error handler and timeouts
	app := fiber.New(fiber.Config{
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// Default to Internal Server Error if no specific Fiber error code
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}

			// Return a structured JSON error response
			return c.Status(code).JSON(fiber.Map{
				"success": false,
				"error": fiber.Map{
					"code":    code,
					"message": err.Error(),
				},
			})
		},
	})

	// --- Global Endpoints (outside /api/v1 group) ---

	// Health check endpoint for external monitoring tools (e.g., Docker HEALTHCHECK)
	// This specifically addresses the requirement: http://localhost:8080/health
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":  "ok",
			"service": "ms-auth",
		})
	})

	// Swagger documentation endpoint
	app.Get("/swagger/*", swagger.HandlerDefault)

	// --- Application Bootstrap ---
	// Bootstrap the application: This function handles database initialization,
	// repository setup, service creation, and registers all API routes.
	// It also returns a database connection and a cleanup function to be deferred.
	_, cleanupDB := routes.BootstrapApp(app, cfg)
	defer cleanupDB() // Ensure database connection is closed when main exits

	// --- Server Start ---
	// Start the Fiber server in a separate goroutine to avoid blocking the main thread
	go func() {
		addr := cfg.Server.Host + ":" + cfg.Server.Port
		log.Printf("🚀 Server starting on %s", addr)
		if err := app.Listen(addr); err != nil {
			log.Fatalf("Failed to start server: %v", err) // Use Fatalf to ensure program exits on failure
		}
	}()

	// --- Graceful Shutdown ---
	// Create a channel to listen for OS signals (Interrupt/SIGTERM)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM) // Register signals to the channel

	<-c // Block until a signal is received

	log.Println("🔄 Gracefully shutting down...")

	// Create a context with a timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel() // Ensure the context's resources are released

	// Attempt to shut down the Fiber app gracefully within the timeout
	if err := app.ShutdownWithContext(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err) // Log fatal if shutdown fails
	}

	log.Println("✅ Server exited")
}
