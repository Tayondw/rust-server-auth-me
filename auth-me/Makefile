# Makefile for auth-me project

.PHONY: help build run test clean setup dev docker-up docker-down migrate

# Default target
help:
	@echo "Available commands:"
	@echo "  setup      - Set up development environment"
	@echo "  dev        - Run in development mode"
	@echo "  build      - Build the application"
	@echo "  run        - Run the application"
	@echo "  test       - Run tests"
	@echo "  clean      - Clean build artifacts"
	@echo "  docker-up  - Start Docker services"
	@echo "  docker-down- Stop Docker services"
	@echo "  migrate    - Run database migrations"
	@echo "  reset-db   - Reset database (development only)"

# Set up development environment
setup:
	@echo "Setting up development environment..."
	cp .env.example .env
	@echo "Please edit .env file with your configuration"
	cargo install diesel_cli --no-default-features --features postgres
	@echo "Setup complete! Edit .env and run 'make dev'"

# Development mode with auto-reload
dev:
	@echo "Starting development server..."
	cargo install cargo-watch
	cargo watch -x run

# Build the application
build:
	@echo "Building application..."
	cargo build --release

# Run the application
run:
	@echo "Running application..."
	cargo run

# Run tests
test:
	@echo "Running tests..."
	cargo test

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean

# Docker commands
docker-up:
	@echo "Starting Docker services..."
	docker-compose up -d

docker-down:
	@echo "Stopping Docker services..."
	docker-compose down

docker-rebuild:
	@echo "Rebuilding Docker services..."
	docker-compose down
	docker-compose build --no-cache
	docker-compose up -d

# Database operations
migrate:
	@echo "Running database migrations..."
	diesel migration run

reset-db:
	@echo "Resetting database (WARNING: This will delete all data)..."
	diesel database reset
	diesel migration run

# Create new migration
migration:
	@read -p "Enter migration name: " name; \
	diesel migration generate $$name

# Development database setup
db-setup:
	@echo "Setting up database..."
	diesel setup
	diesel migration run

# Check code formatting and linting
check:
	@echo "Checking code format and running clippy..."
	cargo fmt --check
	cargo clippy -- -D warnings

# Format code
fmt:
	@echo "Formatting code..."
	cargo fmt

# Generate documentation
docs:
	@echo "Generating documentation..."
	cargo doc --open

# Production build
prod-build:
	@echo "Building for production..."
	cargo build --release

# Install dependencies
deps:
	@echo "Installing dependencies..."
	cargo build

# Run specific test
test-specific:
	@read -p "Enter test name: " test; \
	cargo test $$test

# View logs
logs:
	docker-compose logs -f app

# Backup database
backup-db:
	@echo "Creating database backup..."
	docker-compose exec postgres pg_dump -U postgres auth_me_db > backup_$(shell date +%Y%m%d_%H%M%S).sql

# Restore database
restore-db:
	@read -p "Enter backup file path: " file; \
	docker-compose exec -T postgres psql -U postgres auth_me_db < $$file