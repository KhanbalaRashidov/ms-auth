.PHONY: help build run test clean docker-build docker-run docker-stop docker-clean dev prod migrate docs

# Default target
help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development commands
build: ## Build the application binary
	@echo "Building ms-auth..."
	@go build -ldflags="-s -w" -o bin/ms-auth ./cmd/main.go
	@echo "✅ Build completed!"

run: ## Run the application locally
	@echo "Starting ms-auth..."
	@go run ./cmd/main.go

dev: ## Run in development mode with air (hot reload)
	@echo "Starting development server with hot reload..."
	@air

test: ## Run tests
	@echo "Running tests..."
	@go test -v -race -cover ./...

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

lint: ## Run golangci-lint
	@echo "Running linter..."
	@golangci-lint run

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@echo "✅ Cleaned!"

# Docker commands
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t ms-auth:latest .
	@echo "✅ Docker image built!"

docker-run: ## Run with docker-compose
	@echo "Starting services with docker-compose..."
	@docker-compose up -d
	@echo "✅ Services started!"

docker-run-build: ## Build and run with docker-compose
	@echo "Building and starting services..."
	@docker-compose up -d --build
	@echo "✅ Services built and started!"

docker-stop: ## Stop docker-compose services
	@echo "Stopping services..."
	@docker-compose down
	@echo "✅ Services stopped!"

docker-clean: ## Clean Docker images and volumes
	@echo "Cleaning Docker..."
	@docker-compose down -v --rmi all --remove-orphans
	@docker system prune -f
	@echo "✅ Docker cleaned!"

docker-logs: ## Show docker-compose logs
	@docker-compose logs -f

docker-logs-app: ## Show only ms-auth logs
	@docker-compose logs -f ms-auth

# Database commands
migrate-up: ## Run database migrations up
	@echo "Running database migrations..."
	@go run ./cmd/migrate/main.go up
	@echo "✅ Migrations completed!"

migrate-down: ## Run database migrations down
	@echo "Rolling back database migrations..."
	@go run ./cmd/migrate/main.go down
	@echo "✅ Migrations rolled back!"

migrate-reset: ## Reset database (down + up)
	@echo "Resetting database..."
	@make migrate-down
	@make migrate-up
	@echo "✅ Database reset!"

db-seed: ## Seed database with test data
	@echo "Seeding database..."
	@go run ./cmd/seed/main.go
	@echo "✅ Database seeded!"

# Production commands
prod: ## Run production environment
	@echo "Starting production environment..."
	@docker-compose -f docker-compose.yml up -d
	@echo "✅ Production environment started!"

prod-build: ## Build and run production environment
	@echo "Building and starting production environment..."
	@docker-compose -f docker-compose.yml up -d --build
	@echo "✅ Production environment built and started!"

prod-stop: ## Stop production environment
	@echo "Stopping production environment..."
	@docker-compose -f docker-compose.yml down
	@echo "✅ Production environment stopped!"

# Admin tools
admin-start: ## Start admin tools (pgAdmin, Redis Commander)
	@echo "Starting admin tools..."
	@docker-compose --profile admin up -d
	@echo "✅ Admin tools started!"
	@echo "📊 pgAdmin: http://localhost:5050 (admin@ms-auth.com / admin123)"
	@echo "📊 Redis Commander: http://localhost:8081"

admin-stop: ## Stop admin tools
	@echo "Stopping admin tools..."
	@docker-compose --profile admin down
	@echo "✅ Admin tools stopped!"

# Documentation
docs-gen: ## Generate API documentation
	@echo "Generating API documentation..."
	@swag init -g ./cmd/main.go -o ./docs
	@echo "✅ API documentation generated!"

docs-serve: ## Serve API documentation
	@echo "Serving API documentation..."
	@swagger serve -F=swagger docs/swagger.yaml

# Utility commands
logs: ## Show application logs
	@tail -f logs/app.log

ps: ## Show running containers
	@docker-compose ps

health: ## Check application health
	@curl -f http://localhost:9090/api/v1/health || echo "❌ Service not healthy"

status: ## Show service status
	@echo "🔍 Checking service status..."
	@curl -s http://localhost:9090/api/v1/health | jq '.' || echo "❌ Service not responding"
	@echo ""
	@echo "📊 Container status:"
	@docker-compose ps

# Setup commands
setup: ## Setup development environment
	@echo "Setting up development environment..."
	@cp .env.example .env
	@go mod download
	@make docker-run
	@sleep 10
	@make migrate-up
	@echo "✅ Development environment setup completed!"

# Quality assurance
qa: lint test ## Run quality assurance (lint + test)

# Release commands
release-build: ## Build release version
	@echo "Building release version..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/ms-auth-linux ./cmd/main.go
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/ms-auth-windows.exe ./cmd/main.go
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/ms-auth-macos ./cmd/main.go
	@echo "✅ Release builds completed!"

# Environment info
env-info: ## Show environment information
	@echo "🔍 Environment Information:"
	@echo "Go version: $(shell go version)"
	@echo "Docker version: $(shell docker --version)"
	@echo "Docker Compose version: $(shell docker-compose --version)"
	@echo "Current directory: $(shell pwd)"
	@echo "Git branch: $(shell git branch --show-current 2>/dev/null || echo 'N/A')"
	@echo "Git commit: $(shell git rev-parse --short HEAD 2>/dev/null || echo 'N/A')"