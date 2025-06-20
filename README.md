# MS-Auth - Microservice Authentication Service

A comprehensive authentication microservice built with Go, Fiber, and PostgreSQL, implementing JWT-based authentication with Multi-Factor Authentication (MFA) support.

## Features

### 🔐 Authentication & Authorization
- **JWT-based Authentication** with access and refresh tokens
- **Multi-Factor Authentication (MFA)** using TOTP
- **Role-based Access Control** with admin privileges
- **Session Management** with device tracking
- **Password Security** with history tracking and complexity validation
- **Rate Limiting** for sensitive endpoints

### 👤 User Management
- User registration and profile management
- Email and phone verification
- Password reset functionality
- Account status management (active, suspended, locked)
- Soft and hard delete options

### 🛡️ Security Features
- **Token Blacklisting** for logout and security
- **IP-based Rate Limiting**
- **CORS Protection**
- **Password History** tracking
- **Automatic Cleanup** of expired tokens and data
- **Blacklist Management** for IPs, emails, and usernames

### 📊 Admin Features
- User management and status updates
- Blacklist management
- System monitoring and health checks

## Technology Stack

- **Language**: Go 1.21+
- **Web Framework**: Fiber v2
- **Database**: PostgreSQL with GORM
- **Authentication**: JWT tokens
- **MFA**: TOTP (Time-based One-Time Password)
- **Password Hashing**: BCrypt
- **Documentation**: Swagger/OpenAPI

## Project Structure

```
ms-auth/
├── internal/
│   ├── adapters/
│   │   ├── input/http/
│   │   │   ├── handlers/     # HTTP handlers
│   │   │   ├── middleware/   # Authentication middleware
│   │   │   └── routes/       # Route definitions
│   │   └── output/
│   │       └── persistence/  # Database repositories
│   ├── config/              # Configuration management
│   ├── core/
│   │   ├── domain/
│   │   │   ├── entities/    # Domain entities
│   │   │   └── services/    # Domain services
│   │   └── ports/           # Interface definitions
│   └── pkg/
│       └── utils/           # Utility functions
```

## API Endpoints

### Authentication Endpoints

#### Public Routes
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/mfa/verify` - Verify MFA code

#### Protected Routes
- `POST /api/auth/logout` - User logout
- `POST /api/auth/change-password` - Change password
- `GET /api/auth/me` - Get current user info
- `POST /api/auth/mfa/enable` - Enable MFA
- `POST /api/auth/mfa/disable` - Disable MFA

### User Management Endpoints

#### User Profile
- `GET /api/users/profile` - Get user profile
- `PUT /api/users/profile` - Update user profile

#### Session Management
- `GET /api/users/sessions` - Get active sessions
- `DELETE /api/users/sessions/:session_id` - Revoke specific session
- `DELETE /api/users/sessions` - Revoke all sessions

#### Verification
- `POST /api/users/verify-email` - Send email verification
- `POST /api/users/verify-email/confirm` - Confirm email verification
- `POST /api/users/verify-phone` - Send phone verification
- `POST /api/users/verify-phone/confirm` - Confirm phone verification

### Admin Endpoints

#### User Management
- `GET /api/admin/users` - List all users
- `GET /api/admin/users/:user_id` - Get user by ID
- `PUT /api/admin/users/:user_id/status` - Update user status
- `PUT /api/admin/users/:user_id/params` - Update user role/group
- `DELETE /api/admin/users/:user_id` - Delete user

#### Blacklist Management
- `GET /api/admin/blacklist` - Get blacklist entries
- `POST /api/admin/blacklist` - Add to blacklist
- `DELETE /api/admin/blacklist/:blacklist_id` - Remove from blacklist

### Internal Endpoints
- `POST /api/validate-token` - Token validation for other microservices
- `GET /api/actuator/health` - Health check endpoint

## Authentication Flow

### Standard Login
1. User submits credentials to `/api/auth/login`
2. System validates credentials
3. If MFA is disabled: Returns access + refresh token pair
4. If MFA is enabled: Returns MFA challenge token

### MFA Login
1. User submits MFA code to `/api/auth/mfa/verify` with challenge token
2. System validates MFA code
3. Returns access + refresh token pair

### Token Refresh
1. Client sends refresh token to `/api/auth/refresh`
2. System validates refresh token
3. Returns new access + refresh token pair

## Request/Response Examples

### User Registration
```json
POST /api/auth/register
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

### User Login
```json
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "device_id": "web-browser",
  "remember": false
}
```

### Enable MFA
```json
POST /api/auth/mfa/enable
{
  "password": "SecurePassword123!"
}
```

### Update Profile
```json
PUT /api/users/profile
{
  "first_name": "Jane",
  "last_name": "Smith",
  "avatar": "https://example.com/avatar.jpg",
  "metadata": {
    "preferences": {
      "theme": "dark",
      "language": "en"
    }
  }
}
```

## Security Features

### Rate Limiting
- **Login attempts**: Configurable rate limiting per IP
- **Registration attempts**: Configurable rate limiting per IP
- **General API**: Configurable requests per minute

### Token Security
- **Access tokens**: Short-lived (configurable expiration)
- **Refresh tokens**: Longer-lived with rotation
- **MFA challenge tokens**: Very short-lived for MFA flow
- **Reset tokens**: Time-limited for password reset

### Password Security
- **BCrypt hashing** with configurable complexity
- **Password history** tracking to prevent reuse
- **Complexity requirements** (configurable)
- **Automatic cleanup** of old password history

## Configuration

The service uses a configuration structure that includes:

```go
type Config struct {
    JWT struct {
        SecretKey string
        Issuer    string
        Audience  string
    }
    
    Password struct {
        Complexity PasswordComplexityConfig
    }
    
    RateLimit struct {
        RequestsPerMinute  int
        LoginAttempts      int
        LoginWindow        time.Duration
        RegisterAttempts   int
        RegisterWindow     time.Duration
    }
    
    Blacklist struct {
        AutoCleanup       bool
        CleanupInterval   time.Duration
    }
}
```

## Background Tasks

The service runs automatic cleanup tasks:

- **Token Cleanup**: Removes expired tokens every hour
- **Blacklist Cleanup**: Removes expired blacklist entries (if enabled)
- **Password History Cleanup**: Removes old password history every 24 hours

## Error Handling

The service uses consistent error responses:

```json
{
  "success": false,
  "message": "Error description",
  "error": {
    "code": "ERROR_CODE",
    "details": "Detailed error information"
  }
}
```

## Success Responses

Standard success response format:

```json
{
  "success": true,
  "message": "Operation successful",
  "data": {
    // Response data
  }
}
```

## Installation & Setup

1. **Clone the repository**
2. **Set up PostgreSQL database**
3. **Configure environment variables**
4. **Run database migrations**
5. **Start the service**

```bash
go run main.go
```

## API Documentation

The service includes Swagger/OpenAPI documentation accessible at `/swagger/` endpoint when running in development mode.

## Health Monitoring

- **Health Check**: `GET /api/actuator/health`
- **Service Status**: Returns service health and version information

## Inter-Service Communication

The service provides a token validation endpoint for other microservices:

```json
POST /api/validate-token
{
  "token": "jwt-access-token"
}
```

Response:
```json
{
  "valid": true,
  "claims": {
    "user_id": "uuid",
    "username": "user@example.com",
    "email": "user@example.com",
    "role": "user"
  }
}
```
