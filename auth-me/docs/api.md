# Auth-Me API Documentation

## Overview

The Auth-Me API provides comprehensive authentication and user management capabilities. All endpoints return JSON responses and use standard HTTP status codes.

## Base URL

```
http://localhost:8080
```

## Authentication

Most endpoints require authentication via JWT tokens. Include the token in the request header:

```http
Authorization: Bearer <your-jwt-token>
```

Alternatively, tokens can be sent via secure HTTP-only cookies (recommended for web applications).

## Content Type

All request bodies should be sent as JSON:

```http
Content-Type: application/json
```

## Rate Limiting

API requests are rate-limited to prevent abuse:
- Default: 60 requests per minute per IP address
- Rate limit headers are included in responses

## Error Responses

All errors follow a consistent format:

```json
{
  "status": "fail",
  "message": "Error description"
}
```

Common HTTP status codes:
- `400` - Bad Request (validation errors)
- `401` - Unauthorized (authentication required)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict (duplicate data)
- `429` - Too Many Requests (rate limited)
- `500` - Internal Server Error

## Authentication Endpoints

### POST /auth/signup

Register a new user account.

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "username": "johndoe",
  "password": "SecurePass123!",
  "passwordConfirm": "SecurePass123!",
  "terms_accepted": true
}
```

**Validation Rules:**
- `name`: 1-25 characters
- `email`: Valid email format
- `username`: 1-25 characters, alphanumeric + underscores only
- `password`: 8-25 characters, must contain uppercase, number, and special character
- `passwordConfirm`: Must match password
- `terms_accepted`: Must be true

**Response (200):**
```json
{
  "message": "Please check your email and click the verification link to complete your registration."
}
```

### GET /auth/verify

Verify user email address.

**Query Parameters:**
- `token` (required): Email verification token

**Response (200):**
```json
{
  "message": "Email verified successfully and account created",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "creation_type": "SelfSignup",
  "welcome_email_sent": true
}
```

### POST /auth/login

Authenticate user and receive JWT tokens.

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

**Response (200):**
```json
{
  "status": "success",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Note:** Refresh token is set as HTTP-only cookie.

### POST /auth/refresh

Refresh access token using refresh token.

**Authentication:** Requires refresh token cookie

**Response (200):**
```json
{
  "status": "success",
  "message": "Tokens refreshed successfully"
}
```

### POST /auth/logout

Logout user and invalidate tokens.

**Authentication:** Required

**Response (200):**
```json
{
  "status": "success",
  "message": "Successfully logged out"
}
```

### POST /auth/forgot-password

Request password reset email.

**Request Body:**
```json
{
  "email": "john@example.com"
}
```

**Response (200):**
```json
{
  "message": "Password reset link has been sent to your email.",
  "status": "success"
}
```

### POST /auth/reset-password

Reset password using reset token.

**Request Body:**
```json
{
  "token": "reset-token-from-email",
  "new_password": "NewSecurePass123!",
  "new_password_confirm": "NewSecurePass123!"
}
```

**Response (200):**
```json
{
  "message": "Password has been successfully reset.",
  "status": "success"
}
```

## User Management Endpoints

### GET /api/users/me

Get current user profile.

**Authentication:** Required

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "name": "John Doe",
      "email": "john@example.com",
      "username": "johndoe",
      "verified": true,
      "role": "user",
      "createdAt": "2024-01-15T10:30:00Z",
      "updatedAt": "2024-01-15T10:30:00Z"
    }
  }
}
```

### PATCH /api/users/me

Update current user profile.

**Authentication:** Required

**Request Body (all fields optional):**
```json
{
  "name": "John Smith",
  "email": "johnsmith@example.com",
  "username": "johnsmith",
  "password": "NewPassword123!"
}
```

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "user": {
      // Updated user object
    }
  }
}
```

### DELETE /api/users/me

Delete current user account.

**Authentication:** Required

**Request Body:**
```json
{
  "password": "current-password"
}
```

**Response (204):**
```json
{
  "message": "Account deleted successfully",
  "status": 204
}
```

### PATCH /api/users/me/password

Change current user password.

**Authentication:** Required

**Request Body:**
```json
{
  "current_password": "CurrentPass123!",
  "new_password": "NewPass123!"
}
```

**Response (200):**
```json
{
  "status": "success",
  "message": "Password changed successfully"
}
```

## Admin Endpoints

### GET /api/admin/users

List all users (paginated).

**Authentication:** Admin required

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10, max: 50)

**Response (200):**
```json
{
  "status": "success",
  "users": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "name": "John Doe",
      "email": "john@example.com",
      "username": "johndoe",
      "verified": true,
      "role": "user",
      "createdAt": "2024-01-15T10:30:00Z",
      "updatedAt": "2024-01-15T10:30:00Z"
    }
  ],
  "results": 1,
  "page": 1,
  "limit": 10,
  "total_pages": 1
}
```

### POST /api/admin/users

Create new user (admin only).

**Authentication:** Admin required

**Request Body:**
```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "username": "janedoe",
  "password": "SecurePass123!",
  "verified": true,
  "role": "user",
  "send_welcome_email": true,
  "force_password_change": false
}
```

**Response (200):**
```json
{
  "message": "User created successfully",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "temporary_password": null,
  "verification_required": false
}
```

### GET /api/admin/users/{id}

Get specific user by ID.

**Authentication:** Admin required

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "user": {
      // User object
    }
  }
}
```

### PATCH /api/admin/users/{id}

Update specific user.

**Authentication:** Admin required

**Request Body (all fields optional):**
```json
{
  "name": "Updated Name",
  "email": "updated@example.com",
  "username": "updateduser",
  "role": "moderator",
  "verified": true
}
```

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "user": {
      // Updated user object
    }
  }
}
```

### DELETE /api/admin/users/{id}

Delete specific user.

**Authentication:** Admin required

**Response (204):**
```json
{
  "message": "User deleted successfully",
  "status": 204
}
```

### GET /api/admin/users/search

Search and filter users.

**Authentication:** Admin required

**Query Parameters:**
- `page` (optional): Page number
- `limit` (optional): Items per page
- `search` (optional): Search term (name, email, username)
- `role` (optional): Filter by role
- `verified` (optional): Filter by verification status

**Response (200):**
```json
{
  "status": "success",
  "users": [
    // Filtered user objects
  ],
  "results": 5,
  "page": 1,
  "limit": 10,
  "total_pages": 1
}
```

### GET /api/admin/users/statistics

Get user statistics.

**Authentication:** Admin required

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "total_users": 150,
    "verified_users": 140,
    "unverified_users": 10,
    "admin_users": 2,
    "moderator_users": 5,
    "regular_users": 143
  }
}
```

## Bulk Operations

### DELETE /api/admin/users/bulk/delete

Delete multiple users.

**Authentication:** Admin required

**Request Body:**
```json
[
  "123e4567-e89b-12d3-a456-426614174000",
  "123e4567-e89b-12d3-a456-426614174001"
]
```

**Response (200):**
```json
{
  "status": "success",
  "affected_count": 2,
  "message": "Successfully deleted 2 users"
}
```

### PATCH /api/admin/users/bulk/update-roles

Update roles for multiple users.

**Authentication:** Admin required

**Request Body:**
```json
{
  "user_ids": [
    "123e4567-e89b-12d3-a456-426614174000",
    "123e4567-e89b-12d3-a456-426614174001"
  ],
  "new_role": "moderator"
}
```

**Response (200):**
```json
{
  "status": "success",
  "affected_count": 2,
  "message": "Successfully updated roles for 2 users to moderator"
}
```

### POST /api/admin/users/bulk-verify

Verify multiple users.

**Authentication:** Admin required

**Request Body:**
```json
[
  "123e4567-e89b-12d3-a456-426614174000",
  "123e4567-e89b-12d3-a456-426614174001"
]
```

**Response (200):**
```json
{
  "status": "success",
  "affected_count": 2,
  "message": "Successfully verified 2 users"
}
```

## Cache Management

### GET /api/cache/statistics

Get cache statistics.

**Authentication:** Admin required

**Response (200):**
```json
{
  "status": "success",
  "message": "Cache statistics endpoint - implement based on Redis setup"
}
```

### POST /api/cache/invalidate

Invalidate cache by pattern.

**Authentication:** Admin required

**Request Body:**
```json
{
  "pattern": "user:*"
}
```

**Response (200):**
```json
{
  "status": "success",
  "invalidated_count": 15,
  "message": "Invalidated 15 cache keys matching pattern: user:*"
}
```

### POST /api/cache/cleanup

Manual cache cleanup.

**Authentication:** Admin required

**Response (200):**
```json
{
  "status": "success",
  "cleaned_count": 5,
  "message": "Manually cleaned up 5 expired cache entries"
}
```

## Health Check

### GET /health

Check application health status.

**Response (200):**
```json
{
  "status": "healthy",
  "timestamp": 1640995200,
  "uptime_seconds": 3600,
  "version": "0.1.0",
  "environment": "development",
  "database_status": "healthy",
  "redis_status": "healthy",
  "email_status": "configured"
}
```

## Security Headers

All responses include security headers:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy: [environment-specific]`

## CSRF Protection

For state-changing operations, include CSRF token:

### GET /csrf-token

Get CSRF token for client-side applications.

**Response (200):**
```json
{
  "csrf_token": "abc123def456..."
}
```

Include token in `X-CSRF-Token` header for protected endpoints.

## Websockets (Future)

WebSocket endpoints for real-time features:
- `ws://localhost:8080/ws/notifications` - Real-time notifications
- `ws://localhost:8080/ws/admin/metrics` - Live admin metrics

## SDK Examples

### JavaScript/TypeScript

```javascript
const authMe = new AuthMeClient({
  baseUrl: 'http://localhost:8080',
  apiKey: 'your-api-key'
});

// Login
const { token } = await authMe.auth.login({
  email: 'user@example.com',
  password: 'password'
});

// Get current user
const user = await authMe.users.getCurrentUser();

// Create user (admin)
const newUser = await authMe.admin.users.create({
  name: 'New User',
  email: 'new@example.com',
  username: 'newuser',
  role: 'user'
});
```

### Python

```python
from auth_me_client import AuthMeClient

client = AuthMeClient(base_url='http://localhost:8080')

# Login
token = client.auth.login(
    email='user@example.com',
    password='password'
)

# Get current user
user = client.users.get_current_user()

# Create user (admin)
new_user = client.admin.users.create(
    name='New User',
    email='new@example.com',
    username='newuser',
    role='user'
)
```

## Changelog

### v0.1.0
- Initial API release
- Basic authentication endpoints
- User management
- Admin functionality
- Cache management
- Health checks