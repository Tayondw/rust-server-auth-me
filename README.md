# Auth-Me: Comprehensive Authentication System

A robust, production-ready authentication and user management system built with Rust, Axum, and PostgreSQL.

## Features

### Core Authentication
- **JWT-based Authentication** with access and refresh tokens
- **Email Verification** with secure token-based confirmation
- **Password Reset** functionality with expiring tokens
- **Role-based Access Control** (Admin, Manager, User, Moderator)
- **Secure Password Hashing** using Argon2

### User Management
- **Self-registration** with email verification
- **Admin user creation** with customizable permissions
- **Profile management** (self-update and admin management)
- **Bulk operations** (delete, verify, role updates)
- **Advanced user search** and filtering

### Security Features
- **CSRF Protection** with token-based validation
- **Rate Limiting** to prevent abuse
- **Security Headers** (HSTS, CSP, X-Frame-Options, etc.)
- **CORS Configuration** for cross-origin requests
- **Input Validation** with comprehensive error handling

### Performance & Caching
- **Redis-based Caching** with tag-based invalidation
- **Connection Pooling** for database and email services
- **Template Caching** for email templates
- **Sophisticated Cache Management** with automatic cleanup

### Email System
- **HTML Email Templates** with placeholder substitution
- **SMTP Connection Pooling** for high-volume sending
- **Batch Email Processing** with concurrent sending
- **Template Caching** (memory + Redis) for performance

## Project Structure

```
auth-me/
├── src/
│   ├── lib.rs           # Library entry point (public API)
│   ├── main.rs          # Binary entry point (server)
│   ├── config/          # Configuration management
│   ├── connection/      # Database & email connections
│   ├── dto/             # Data Transfer Objects
│   ├── email/           # Email services & templates
│   ├── errors.rs        # Error handling
│   ├── handlers/        # HTTP request handlers
│   ├── middleware/      # Authentication, CORS, security
│   ├── models/          # Database models
│   ├── repositories/    # Data access layer
│   ├── routes/          # Route definitions
│   ├── schema.rs        # Database schema
│   ├── services/        # Business logic
│   └── utils/           # Utility functions
├── migrations/          # Database migrations
├── docker-compose.yml   # Development environment
├── Dockerfile          # Container configuration
└── Makefile           # Development commands
```

## 🛠️ Setup & Installation

### Prerequisites
- Rust 1.75+
- PostgreSQL 13+
- Redis 6+
- Docker & Docker Compose (optional)

### Quick Start with Docker

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/auth-me.git
   cd auth-me
   ```

2. **Set up environment**
   ```bash
   make setup
   # Edit .env file with your configuration
   ```

3. **Start services**
   ```bash
   make docker-up
   ```

4. **Run migrations**
   ```bash
   make migrate
   ```

The application will be available at `http://localhost:8080`

### Manual Setup

1. **Install dependencies**
   ```bash
   # Install Diesel CLI
   cargo install diesel_cli --no-default-features --features postgres
   
   # Copy environment file
   cp .env.example .env
   ```

2. **Configure environment**
   Edit `.env` file with your database, Redis, and email settings.

3. **Set up database**
   ```bash
   make db-setup
   ```

4. **Run the application**
   ```bash
   make dev
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | `redis://127.0.0.1:6379` |
| `JWT_SECRET` | JWT signing secret | Required |
| `JWT_REFRESH_SECRET` | Refresh token secret | Required |
| `SMTP_*` | Email server configuration | Required |
| `PORT` | Server port | `8080` |
| `ENVIRONMENT` | Environment (development/production) | `development` |

### Initial Admin User

Set these environment variables to create an initial admin user:
```bash
INITIAL_ADMIN_EMAIL=admin@yourcompany.com
INITIAL_ADMIN_USERNAME=admin
INITIAL_ADMIN_PASSWORD=secure-password
INITIAL_ADMIN_NAME=System Administrator
```

## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/signup` | User registration |
| `POST` | `/auth/login` | User login |
| `GET` | `/auth/verify` | Email verification |
| `POST` | `/auth/forgot-password` | Request password reset |
| `POST` | `/auth/reset-password` | Reset password |
| `POST` | `/auth/refresh` | Refresh access token |
| `POST` | `/auth/logout` | User logout |

### User Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/users/me` | Get current user | ✅ |
| `PATCH` | `/api/users/me` | Update current user | ✅ |
| `DELETE` | `/api/users/me` | Delete current user | ✅ |
| `GET` | `/api/admin/users` | List all users | Admin |
| `POST` | `/api/admin/users` | Create user | Admin |
| `PATCH` | `/api/admin/users/{id}` | Update user | Admin |
| `DELETE` | `/api/admin/users/{id}` | Delete user | Admin |

### Example Request/Response

**POST /auth/signup**
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

**Response:**
```json
{
  "message": "Please check your email and click the verification link to complete your registration."
}
```

## Security Features

### Authentication & Authorization
- JWT tokens with configurable expiration
- Role-based access control (RBAC)
- Email verification required for activation
- Secure password hashing with Argon2

### Security Middleware
- CSRF protection with token validation
- Rate limiting per IP address
- Security headers (HSTS, CSP, etc.)
- CORS configuration for cross-origin requests

### Input Validation
- Comprehensive request validation
- SQL injection prevention
- XSS protection through proper encoding

## 📊 Performance & Caching

### Caching Strategy
- **User Data**: 5-minute TTL with tag-based invalidation
- **Search Results**: 30-second TTL for frequently changing data
- **Email Templates**: 1-hour TTL with Redis backing
- **User Lists**: 1-minute TTL with role-based tags

### Cache Invalidation
Sophisticated tag-based cache invalidation ensures data consistency:
- User updates invalidate user-specific and role-based caches
- Bulk operations trigger targeted cache cleanup
- Automatic cleanup of expired cache entries

## Testing

```bash
# Run all tests
make test

# Run specific test
make test-specific

# Run with coverage
cargo test --coverage

# Test as library
cargo test --lib

# Test binary integration
cargo test --bin auth-me
```

## Deployment

### Docker Deployment

1. **Build production image**
   ```bash
   docker build -t auth-me:latest .
   ```

2. **Run with environment**
   ```bash
   docker run -d \
     --name auth-me \
     -p 8080:8080 \
     --env-file .env.production \
     auth-me:latest
   ```

### Production Considerations

- Use strong JWT secrets (generate with `openssl rand -base64 32`)
- Configure proper CORS origins
- Set up SSL/TLS termination
- Use connection pooling for databases
- Monitor Redis memory usage
- Set up log aggregation
- Configure health checks

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

This authentication system can be integrated with various frontend frameworks:
- React/Next.js applications
- Vue.js applications  
- Flutter mobile apps
- Any application requiring JWT-based authentication

## Support

- Create an issue for bug reports
- Use discussions for questions
- Check the wiki for detailed documentation
