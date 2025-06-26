# Contributing to Auth-Me

Thank you for your interest in contributing to Auth-Me! We welcome contributions from the community and are pleased to have you aboard.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, please include as many details as possible:

**Bug Report Template:**

```markdown
**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Environment:**
- OS: [e.g. Ubuntu 20.04]
- Rust version: [e.g. 1.75.0]
- Auth-Me version: [e.g. 0.1.0]
- Database: [e.g. PostgreSQL 15]

**Additional context**
Add any other context about the problem here.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use case**: Describe the problem you're trying to solve
- **Proposed solution**: Describe your ideal solution
- **Alternatives**: Describe alternative solutions you've considered
- **Additional context**: Any other relevant information

### Your First Code Contribution

Unsure where to begin? You can start by looking through these `beginner` and `help-wanted` issues:

- **Beginner issues** - issues that should only require a few lines of code
- **Help wanted issues** - issues that are more involved than beginner issues

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Install dependencies**: `cargo build`
3. **Make your changes**
4. **Add tests** for any new functionality
5. **Ensure tests pass**: `cargo test`
6. **Format your code**: `cargo fmt`
7. **Run clippy**: `cargo clippy`
8. **Update documentation** if needed
9. **Create a pull request**

#### Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update the API documentation if you've made API changes
3. Increase version numbers in any examples files and the README.md to the new version that this Pull Request would represent
4. Your pull request will be reviewed by maintainers

#### Pull Request Template

```markdown
## Description
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] Manual testing completed

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] Any dependent changes have been merged and published
```

## Development Setup

### Prerequisites

- Rust 1.75+
- PostgreSQL 13+
- Redis 6+
- Docker (optional, for testing)

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/auth-me.git
   cd auth-me
   ```

2. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your local configuration
   ```

3. **Install dependencies**
   ```bash
   cargo build
   ```

4. **Set up database**
   ```bash
   # Install Diesel CLI
   cargo install diesel_cli --no-default-features --features postgres
   
   # Run migrations
   diesel setup
   diesel migration run
   ```

5. **Run tests**
   ```bash
   cargo test
   ```

6. **Start development server**
   ```bash
   cargo run
   # Or use cargo-watch for auto-reload
   cargo install cargo-watch
   cargo watch -x run
   ```

### Docker Development

```bash
# Start all services
make docker-up

# Run migrations
make migrate

# View logs
make logs
```

## Coding Standards

### Rust Style Guide

We follow the standard Rust style guide with these additions:

1. **Formatting**: Use `cargo fmt` to format code
2. **Linting**: Use `cargo clippy` and fix all warnings
3. **Documentation**: Document all public APIs with examples
4. **Error handling**: Use proper error types, avoid `unwrap()` in production code
5. **Testing**: Write unit tests for all new functionality

### Code Organization

```
src/
├── config/          # Configuration management
├── models/          # Data models
├── repositories/    # Data access layer
├── services/        # Business logic
├── handlers/        # HTTP request handlers
├── middleware/      # Middleware functions
├── utils/           # Utility functions
└── routes/          # Route definitions
```

### Naming Conventions

- **Functions**: `snake_case`
- **Variables**: `snake_case`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Types**: `PascalCase`
- **Modules**: `snake_case`

### Documentation

- Document all public functions with examples
- Use `//!` for module-level documentation
- Use `///` for function documentation
- Include examples in documentation tests

Example:
```rust
/// Validates user credentials and returns a JWT token
/// 
/// # Arguments
/// 
/// * `email` - The user's email address
/// * `password` - The user's password
/// 
/// # Returns
/// 
/// Returns `Ok(String)` containing the JWT token if successful,
/// or `Err(AuthError)` if authentication fails.
/// 
/// # Examples
/// 
/// ```
/// use auth_me::authenticate_user;
/// 
/// let token = authenticate_user("user@example.com", "password").await?;
/// ```
pub async fn authenticate_user(email: &str, password: &str) -> Result<String, AuthError> {
    // Implementation
}
```

## Testing

### Writing Tests

1. **Unit tests**: Test individual functions in isolation
2. **Integration tests**: Test API endpoints and database interactions
3. **Property tests**: Use quickcheck for property-based testing when appropriate

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_user_creation() {
        // Arrange
        let user_data = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            // ... other fields
        };
        
        // Act
        let result = create_user(user_data).await;
        
        // Assert
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.email, "test@example.com");
    }
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_user_creation

# Run tests with output
cargo test -- --nocapture

# Run integration tests only
cargo test --test integration_tests
```

## Database Migrations

### Creating Migrations

```bash
# Create a new migration
diesel migration generate add_new_table

# Run migrations
diesel migration run

# Rollback last migration
diesel migration revert
```

### Migration Guidelines

1. **Always** test migrations on a copy of production data
2. **Use transactions** for complex migrations
3. **Create indexes concurrently** in production
4. **Add NOT NULL constraints** in separate migrations from column additions
5. **Document** any data transformations

Example migration:
```sql
-- Up migration (up.sql)
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);

-- Down migration (down.sql)
DROP TABLE user_sessions;
```

## Security Guidelines

### Security Checklist

- [ ] Validate all user inputs
- [ ] Use parameterized queries for database operations
- [ ] Sanitize data before logging
- [ ] Use secure random generators for tokens
- [ ] Implement proper rate limiting
- [ ] Follow principle of least privilege
- [ ] Use HTTPS in production
- [ ] Hash passwords with salt
- [ ] Implement CSRF protection
- [ ] Validate JWT tokens properly

### Common Security Issues to Avoid

1. **SQL Injection**: Always use parameterized queries
2. **XSS**: Escape output, use CSP headers
3. **CSRF**: Implement CSRF tokens for state-changing operations
4. **Timing attacks**: Use constant-time comparisons for sensitive data
5. **Information disclosure**: Don't leak internal errors to users

## Performance Guidelines

### Performance Best Practices

1. **Database queries**: Use indexes, avoid N+1 queries
2. **Caching**: Implement appropriate caching strategies
3. **Connection pooling**: Use connection pools for databases and external services
4. **Async operations**: Use async/await for I/O operations
5. **Memory usage**: Avoid unnecessary allocations

### Benchmarking

```bash
# Run benchmarks
cargo bench

# Profile with flamegraph
cargo install flamegraph
cargo flamegraph --bin auth-me
```

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. [ ] Update version in `Cargo.toml`
2. [ ] Update `CHANGELOG.md`
3. [ ] Run full test suite
4. [ ] Update documentation
5. [ ] Create git tag
6. [ ] Build and test Docker image
7. [ ] Create GitHub release
8. [ ] Deploy to staging and test
9. [ ] Deploy to production

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Email**: security@yourdomain.com (for security issues only)

### Documentation

- **API Documentation**: [docs/api.md](docs/api.md)
- **Deployment Guide**: [docs/deployment.md](docs/deployment.md)
- **Architecture Guide**: [docs/architecture.md](docs/architecture.md)

## Recognition

Contributors will be recognized in several ways:

1. **README.md**: Listed in the contributors section
2. **CHANGELOG.md**: Credited for their contributions
3. **GitHub**: Contributor badge on profile
4. **Release notes**: Mentioned in release announcements

## Questions?

Don't hesitate to ask questions! We're here to help:

1. Check the [FAQ](docs/faq.md)
2. Search existing issues
3. Create a new issue or discussion
4. Reach out to maintainers

Thank you for contributing to Auth-Me! 🚀