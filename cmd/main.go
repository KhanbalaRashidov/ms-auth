package main

// @title           ms-auth API
// @version         1.0
// @description     Authentication and User Management Microservice
// @host      localhost:9090/api
// @BasePath  /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" + space + your JWT token
import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	fiberSwagger "github.com/swaggo/fiber-swagger"

	_ "ms-auth/docs" // Import generated Swagger documentation
	"ms-auth/internal/adapters/input/http/routes"
	"ms-auth/internal/config"
)

func main() {
	// Load application configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize Fiber application with custom error handler and timeouts
	app := fiber.New(
		fiber.Config{})

	// Swagger documentation endpoint
	app.Get("/swagger/*", fiberSwagger.WrapHandler)

	_, cleanupDB := routes.BootstrapApp(app, cfg)
	defer cleanupDB() // Ensure database connection is closed when main exits

	go func() {
		addr := cfg.Server.Host + ":" + cfg.Server.Port
		log.Printf("🚀 Server starting on %s", addr)
		if err := app.Listen(addr); err != nil {
			log.Fatalf("Failed to start server: %v", err) // Use Fatalf to ensure program exits on failure
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM) // Register signals to the channel

	<-c

	log.Println("🔄 Gracefully shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel() // Ensure the context's resources are released

	if err := app.ShutdownWithContext(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err) // Log fatal if shutdown fails
	}

	log.Println("✅ Server exited")
}
