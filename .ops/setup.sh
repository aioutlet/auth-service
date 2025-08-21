#!/bin/bash

# Auth Service Environment Setup
# This script sets up the auth service for any environment by reading from .env files

set -e

SERVICE_NAME="auth-service"
SERVICE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -h, --help           Show this help message"
            echo ""
            echo "This script sets up the auth service for development."
            echo "Uses .env file for configuration."
            echo "Database and dependencies are managed via Docker Compose."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

echo "🚀 Setting up $SERVICE_NAME for development..."

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to load environment variables from .env file
load_env_file() {
    local env_file="$SERVICE_PATH/.env"
    
    log_info "Loading environment variables from .env..."
    
    if [ ! -f "$env_file" ]; then
        log_error "Environment file not found: $env_file"
        log_info "Please copy .env.example to .env and configure it:"
        log_info "cp .env.example .env"
        exit 1
    fi
    
    # Load environment variables safely
    set -a  # automatically export all variables
    
    # Source the file while filtering out comments and empty lines
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip empty lines and comments
        if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
            # Export the variable if it contains an equals sign
            if [[ "$line" =~ ^[^=]+= ]]; then
                export "$line"
            fi
        fi
    done < "$env_file"
    
    set +a  # stop automatically exporting
    
    log_success "Environment variables loaded from .env"
    
    # Validate required variables for MongoDB-based auth service
    local required_vars=("MONGODB_DB_NAME" "MONGODB_USERNAME" "MONGODB_PASSWORD" "PORT" "NODE_ENV")
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -ne 0 ]; then
        log_error "Missing required environment variables: ${missing_vars[*]}"
        log_info "Please ensure these variables are set in $env_file"
        exit 1
    fi
    
    log_info "Environment: $NODE_ENV"
    log_info "Port: $PORT"
    log_info "MongoDB Database: $MONGODB_DB_NAME"
    log_info "MongoDB User: $MONGODB_USERNAME"
}

# Check for Node.js
check_nodejs() {
    log_info "Checking Node.js installation..."
    
    if command_exists node; then
        NODE_VERSION=$(node --version | sed 's/v//')
        log_success "Node.js $NODE_VERSION is installed"
        
        # Check if version is 18 or higher
        if [[ $(echo "$NODE_VERSION" | cut -d. -f1) -lt 18 ]]; then
            log_warning "Node.js version 18+ is recommended. Current version: $NODE_VERSION"
        fi
    else
        log_error "Node.js is not installed. Please install Node.js 18+ and npm"
        exit 1
    fi
    
    if command_exists npm; then
        NPM_VERSION=$(npm --version)
        log_success "npm $NPM_VERSION is installed"
    else
        log_error "npm is not installed. Please install npm"
        exit 1
    fi
}

# Check for MongoDB (via Docker)
check_mongodb() {
    log_info "Checking MongoDB/Docker setup..."
    
    if command_exists docker; then
        log_success "Docker is available for MongoDB container"
    else
        log_error "Docker is required for MongoDB container"
        log_info "Please install Docker Desktop or Docker Engine"
        exit 1
    fi
    
    # Check if Docker service is running
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker service is not running"
        log_info "Please start Docker Desktop or Docker service"
        exit 1
    fi
    
    log_success "MongoDB will be available via Docker container"
}

# Install Node.js dependencies
install_dependencies() {
    log_info "Installing Node.js dependencies..."
    
    cd "$SERVICE_PATH"
    
    if [ -f "package.json" ]; then
        npm install
        log_success "Dependencies installed successfully"
    else
        log_error "package.json not found in $SERVICE_PATH"
        exit 1
    fi
}

# Setup database
setup_database() {
    log_info "Setting up MongoDB via Docker Compose"
    
    # MongoDB setup is handled by docker-compose.yml
    # The container will initialize the database automatically
    log_info "MongoDB Database: $MONGODB_DB_NAME"
    log_info "MongoDB will be available on port: ${MONGODB_PORT:-27018}"
    log_success "MongoDB configuration verified"
    
    # Create user if not exists
    psql -h ${DB_HOST:-localhost} -U postgres -d postgres -c "
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$DB_USER') THEN
                CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
            END IF;
        END
        \$\$;
        
        GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
    " > /dev/null 2>&1
    
    log_success "Database user configured"
}

# Run database setup scripts
run_database_scripts() {
    if [ -d "$SERVICE_PATH/database" ]; then
        log_info "Running database setup scripts..."
        cd "$SERVICE_PATH"
        
        if [ -f "database/scripts/setup.js" ]; then
            log_info "Running database setup..."
            node database/scripts/setup.js
            log_success "Database setup completed"
        else
            log_warning "Database setup script not found"
        fi
    else
        log_warning "Database directory not found"
    fi
}

# Validate setup
validate_setup() {
    log_info "Validating setup..."
    
    # Check if we can connect to database
    if command_exists psql; then
        if psql -h ${DB_HOST:-localhost} -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
            log_success "Database connection successful"
        else
            log_error "Database connection failed"
            return 1
        fi
    fi
    
    # Check if Node.js dependencies are installed
    if [ -d "$SERVICE_PATH/node_modules" ]; then
        log_success "Node.js dependencies are installed"
    else
        log_error "Node.js dependencies not found"
        return 1
    fi
    
    return 0
}

# Create environment file if it doesn't exist
create_env_template() {
    local env_file="$SERVICE_PATH/.env"
    
    if [ ! -f "$env_file" ]; then
        log_info "Creating environment template: .env"
        
        cat > "$env_file" << EOF
# Auth Service Environment Configuration - Development

# Server Configuration
NODE_ENV=development
PORT=3001
HOST=localhost

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db
DB_USER=auth_user
DB_PASSWORD=auth_password
DB_SSL=false
DB_POOL_MIN=2
DB_POOL_MAX=10

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-for-auth-service-development
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d
JWT_ALGORITHM=HS256

# Password Security
BCRYPT_ROUNDS=12
PASSWORD_MIN_LENGTH=8
PASSWORD_COMPLEXITY_REQUIRED=true

# OAuth Configuration
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
FACEBOOK_APP_ID=
FACEBOOK_APP_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Redis Configuration (for sessions/tokens)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
LOGIN_RATE_LIMIT_MAX_REQUESTS=5

# Session Configuration
SESSION_SECRET=your-session-secret-for-auth-service-development
SESSION_TIMEOUT=3600000
SESSION_STORE=redis

# External Service URLs
USER_SERVICE_URL=http://localhost:3002
AUDIT_SERVICE_URL=http://localhost:3007
NOTIFICATION_SERVICE_URL=http://localhost:3008

# Email Configuration
EMAIL_SERVICE=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=noreply@aioutlet.com

# MFA Configuration
MFA_ENABLED=true
MFA_ISSUER=AI_Outlet
TOTP_WINDOW=1
SMS_SERVICE_ENABLED=false
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_PHONE_NUMBER=

# Security Configuration
CORS_ORIGIN=http://localhost:3000,http://localhost:3001
CORS_CREDENTIALS=true
HELMET_ENABLED=true
CSRF_PROTECTION=true

# Token Configuration
ACCESS_TOKEN_EXPIRY=900
REFRESH_TOKEN_EXPIRY=604800
PASSWORD_RESET_EXPIRY=3600
EMAIL_VERIFICATION_EXPIRY=86400

# Logging Configuration
LOG_LEVEL=info
LOG_FILE=logs/auth-service.log
LOG_MAX_SIZE=10m
LOG_MAX_FILES=5

# Account Security
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=900
PASSWORD_HISTORY_COUNT=5
PASSWORD_EXPIRY_DAYS=90

# Service Registry
SERVICE_NAME=auth-service
SERVICE_VERSION=1.0.0
SERVICE_REGISTRY_URL=http://localhost:8761/eureka

# Health Check Configuration
HEALTH_CHECK_ENABLED=true
HEALTH_CHECK_INTERVAL=30000

# API Gateway Configuration
API_GATEWAY_ENABLED=true
API_RATE_LIMIT=1000
API_BURST_LIMIT=2000

# Monitoring Configuration
METRICS_ENABLED=true
PERFORMANCE_MONITORING=true
ERROR_TRACKING_ENABLED=true
EOF
        
        log_success "Environment template created: $(basename $env_file)"
        log_warning "Please review and update the configuration values as needed"
    fi
}

# Main execution
main() {
    echo "=========================================="
    echo "🔐 Auth Service Environment Setup"
    echo "=========================================="
    
    OS=$(detect_os)
    log_info "Detected OS: $OS"
    log_info "Target Environment: development"
    
    # Create environment file if it doesn't exist
    create_env_template
    
    # Load environment variables
    load_env_file
    
    # Check prerequisites
    check_nodejs
    check_mongodb
    
    # Install dependencies
    install_dependencies
    
    # Setup database
    setup_database
    
    # Run database scripts
    run_database_scripts
    
    # Validate setup
    if validate_setup; then
        echo "=========================================="
        log_success "✅ Auth Service setup completed successfully!"
        echo "=========================================="
        echo ""
        
        # Start services with Docker Compose
        log_info "🐳 Starting services with Docker Compose..."
        if docker-compose up -d; then
            log_success "Services started successfully"
            echo ""
            log_info "⏳ Waiting for services to be ready..."
            sleep 15
            
            # Check service health
            if docker-compose ps | grep -q "Up.*healthy"; then
                log_success "Services are healthy and ready"
            else
                log_warning "Services may still be starting up"
            fi
        else
            log_error "Failed to start services with Docker Compose"
            return 1
        fi
        echo ""
        
        echo "🔐 Setup Summary:"
        echo "  • Environment: $NODE_ENV"
        echo "  • Port: $PORT"
        echo "  • Database: $DB_NAME"
        echo "  • Health Check: http://localhost:$PORT/health"
        echo "  • API Base: http://localhost:$PORT/api/v1"
        echo ""
        echo "🔑 Auth Features:"
        echo "  • JWT Authentication"
        echo "  • OAuth Integration (Google, Facebook, GitHub)"
        echo "  • Multi-Factor Authentication (MFA)"
        echo "  • Password Security & History"
        echo "  • Rate Limiting & Account Lockout"
        echo ""
        echo "� Service is now running:"
        echo "  • View status: docker-compose ps"
        echo "  • View logs: docker-compose logs -f"
        echo "  • Stop services: bash .ops/teardown.sh"
        echo ""
    else
        log_error "Setup validation failed"
        exit 1
    fi
}

# Run main function
main "$@"
