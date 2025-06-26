// Configuration validation utilities

use regex::Regex;
use std::collections::HashSet;
use url::Url;

use crate::config::{ ConfigError, database::RawDatabaseConfig };

/// Comprehensive configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate all configuration settings
    pub fn validate_all(config: &RawDatabaseConfig) -> Result<(), ConfigError> {
        Self::validate_database_config(config)?;
        Self::validate_jwt_config(config)?;
        Self::validate_email_config(config)?;
        Self::validate_redis_config(config)?;
        Self::validate_aws_config(config)?;
        Self::validate_security_config(config)?;
        Ok(())
    }

    /// Validate database configuration
    pub fn validate_database_config(config: &RawDatabaseConfig) -> Result<(), ConfigError> {
        // Validate database URL format
        if
            !config.database_url.starts_with("postgresql://") &&
            !config.database_url.starts_with("postgres://")
        {
            return Err(
                ConfigError::Config(
                    "DATABASE_URL must be a valid PostgreSQL connection string".to_string()
                )
            );
        }

        // Try to parse the URL to validate format
        Url::parse(&config.database_url).map_err(|_| {
            ConfigError::Config("DATABASE_URL is not a valid URL".to_string())
        })?;

        // Validate schema name
        if config.schema.is_empty() || config.schema.contains(' ') {
            return Err(
                ConfigError::Config("SCHEMA must be a valid PostgreSQL schema name".to_string())
            );
        }

        Ok(())
    }

    /// Validate JWT configuration
    pub fn validate_jwt_config(config: &RawDatabaseConfig) -> Result<(), ConfigError> {
        // Validate JWT secret strength
        if config.jwt_secret.len() < 32 {
            return Err(
                ConfigError::Config(
                    "JWT_SECRET must be at least 32 characters long for security".to_string()
                )
            );
        }

        if config.jwt_refresh_secret.len() < 32 {
            return Err(
                ConfigError::Config(
                    "JWT_REFRESH_SECRET must be at least 32 characters long for security".to_string()
                )
            );
        }

        // Check that secrets are different
        if config.jwt_secret == config.jwt_refresh_secret {
            return Err(
                ConfigError::Config(
                    "JWT_SECRET and JWT_REFRESH_SECRET must be different".to_string()
                )
            );
        }

        // Validate expiration times
        if config.jwt_expires_in < 1 || config.jwt_expires_in > 1440 {
            // 1 minute to 24 hours
            return Err(
                ConfigError::Config("JWT_EXPIRES_IN must be between 1 and 1440 minutes".to_string())
            );
        }

        if config.jwt_refresh_expires_in < 60 || config.jwt_refresh_expires_in > 43200 {
            // 1 hour to 30 days
            return Err(
                ConfigError::Config(
                    "JWT_REFRESH_EXPIRES_IN must be between 60 and 43200 minutes".to_string()
                )
            );
        }

        // Refresh token should be longer-lived than access token
        if config.jwt_refresh_expires_in <= config.jwt_expires_in {
            return Err(
                ConfigError::Config(
                    "JWT_REFRESH_EXPIRES_IN must be greater than JWT_EXPIRES_IN".to_string()
                )
            );
        }

        Ok(())
    }

    /// Validate email configuration
    pub fn validate_email_config(config: &RawDatabaseConfig) -> Result<(), ConfigError> {
        // Validate SMTP server
        if config.smtp_server.is_empty() {
            return Err(ConfigError::Config("SMTP_SERVER cannot be empty".to_string()));
        }

        // Validate SMTP port
        if config.smtp_port == 0 || config.smtp_port > 65535 {
            return Err(
                ConfigError::Config("SMTP_PORT must be a valid port number (1-65535)".to_string())
            );
        }

        // Common SMTP ports validation
        let valid_smtp_ports = HashSet::from([25, 465, 587, 2525]);
        if !valid_smtp_ports.contains(&config.smtp_port) {
            println!(
                "Warning: SMTP_PORT {} is not a standard SMTP port (25, 465, 587, 2525)",
                config.smtp_port
            );
        }

        // Validate email addresses
        Self::validate_email_address(&config.smtp_from_address)?;
        Self::validate_email_address(&config.smtp_username)?;

        // Validate SMTP password
        if config.smtp_password.is_empty() {
            return Err(ConfigError::Config("SMTP_PASSWORD cannot be empty".to_string()));
        }

        Ok(())
    }

    /// Validate Redis configuration
    pub fn validate_redis_config(config: &RawDatabaseConfig) -> Result<(), ConfigError> {
        // Validate Redis URL format
        if !config.redis_url.starts_with("redis://") && !config.redis_url.starts_with("rediss://") {
            return Err(
                ConfigError::Config("REDIS_URL must start with redis:// or rediss://".to_string())
            );
        }

        // Try to parse the URL
        Url::parse(&config.redis_url).map_err(|_| {
            ConfigError::Config("REDIS_URL is not a valid URL".to_string())
        })?;

        Ok(())
    }

    /// Validate AWS configuration
    pub fn validate_aws_config(config: &RawDatabaseConfig) -> Result<(), ConfigError> {
        // Validate AWS region
        let valid_regions = HashSet::from([
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-central-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
            "ap-northeast-2",
            "sa-east-1",
            "ca-central-1",
            "eu-north-1",
            "ap-south-1",
        ]);

        if !valid_regions.contains(config.aws_region.as_str()) {
            println!("Warning: AWS_REGION '{}' may not be a valid AWS region", config.aws_region);
        }

        // Validate S3 bucket name format
        if !Self::is_valid_s3_bucket_name(&config.aws_s3_bucket_name) {
            return Err(
                ConfigError::Config("AWS_S3_BUCKET_NAME is not a valid S3 bucket name".to_string())
            );
        }

        // Validate AWS credentials are present
        if config.aws_s3_key.is_empty() {
            return Err(ConfigError::Config("AWS_S3_KEY cannot be empty".to_string()));
        }

        if config.aws_s3_secret.is_empty() {
            return Err(ConfigError::Config("AWS_S3_SECRET cannot be empty".to_string()));
        }

        // Validate AWS access key format (should be 20 characters)
        if config.aws_s3_key.len() != 20 {
            println!("Warning: AWS_S3_KEY should be 20 characters long");
        }

        // Validate AWS secret key format (should be 40 characters)
        if config.aws_s3_secret.len() != 40 {
            println!("Warning: AWS_S3_SECRET should be 40 characters long");
        }

        Ok(())
    }

    /// Validate security configuration
    pub fn validate_security_config(config: &RawDatabaseConfig) -> Result<(), ConfigError> {
        // Validate port number
        if config.port == 0 || config.port > 65535 {
            return Err(
                ConfigError::Config("PORT must be a valid port number (1-65535)".to_string())
            );
        }

        // Validate rate limiting
        if config.rate_limit_requests_per_minute == 0 {
            return Err(
                ConfigError::Config(
                    "RATE_LIMIT_REQUESTS_PER_MINUTE must be greater than 0".to_string()
                )
            );
        }

        if config.rate_limit_requests_per_minute > 10000 {
            println!(
                "Warning: RATE_LIMIT_REQUESTS_PER_MINUTE is very high ({})",
                config.rate_limit_requests_per_minute
            );
        }

        Ok(())
    }

    /// Validate email address format
    fn validate_email_address(email: &str) -> Result<(), ConfigError> {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").map_err(
            |_| ConfigError::Config("Failed to compile email regex".to_string())
        )?;

        if !email_regex.is_match(email) {
            return Err(ConfigError::Config(format!("'{}' is not a valid email address", email)));
        }

        Ok(())
    }

    /// Validate S3 bucket name according to AWS rules
    fn is_valid_s3_bucket_name(name: &str) -> bool {
        // S3 bucket naming rules:
        // - 3-63 characters long
        // - Only lowercase letters, numbers, dots, and hyphens
        // - Must start and end with letter or number
        // - Cannot have consecutive dots
        // - Cannot look like an IP address

        if name.len() < 3 || name.len() > 63 {
            return false;
        }

        let bucket_regex = Regex::new(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$").unwrap();
        if !bucket_regex.is_match(name) {
            return false;
        }

        // Check for consecutive dots
        if name.contains("..") {
            return false;
        }

        // Check if it looks like an IP address
        let ip_regex = Regex::new(r"^\d+\.\d+\.\d+\.\d+$").unwrap();
        if ip_regex.is_match(name) {
            return false;
        }

        true
    }

    /// Validate production-specific requirements
    pub fn validate_production_config(config: &RawDatabaseConfig) -> Result<(), ConfigError> {
        // Check for default/weak values that shouldn't be used in production
        let weak_secrets = HashSet::from([
            "your-super-secret-jwt-key-change-this-in-production",
            "your-super-secret-refresh-key-change-this-in-production",
            "change-this-secure-password",
            "admin",
            "password",
            "test",
        ]);

        if weak_secrets.contains(config.jwt_secret.as_str()) {
            return Err(
                ConfigError::Config(
                    "JWT_SECRET appears to be a default value - change it for production".to_string()
                )
            );
        }

        if weak_secrets.contains(config.jwt_refresh_secret.as_str()) {
            return Err(
                ConfigError::Config(
                    "JWT_REFRESH_SECRET appears to be a default value - change it for production".to_string()
                )
            );
        }

        // Ensure HTTPS is used for production URLs if they're web-facing
        if config.database_url.contains("sslmode=disable") {
            println!("Warning: Database SSL is disabled - consider enabling for production");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::database::RawDatabaseConfig;

    fn create_test_config() -> RawDatabaseConfig {
        RawDatabaseConfig {
            database_url: "postgresql://user:pass@localhost:5432/testdb".to_string(),
            jwt_secret: "a".repeat(32),
            jwt_refresh_secret: "b".repeat(32),
            rust_log: "info".to_string(),
            schema: "public".to_string(),
            jwt_expires_in: 15,
            jwt_refresh_expires_in: 10080,
            redis_url: "redis://localhost:6379".to_string(),
            port: 8080,
            rate_limit_requests_per_minute: 60,
            smtp_server: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            smtp_username: "test@example.com".to_string(),
            smtp_password: "password".to_string(),
            smtp_from_address: "noreply@example.com".to_string(),
            aws_s3_bucket_name: "valid-bucket-name".to_string(),
            aws_s3_key: "A".repeat(20),
            aws_s3_secret: "a".repeat(40),
            aws_region: "us-east-1".to_string(),
        }
    }

    #[test]
    fn test_valid_config() {
        let config = create_test_config();
        assert!(ConfigValidator::validate_all(&config).is_ok());
    }

    #[test]
    fn test_invalid_database_url() {
        let mut config = create_test_config();
        config.database_url = "invalid-url".to_string();
        assert!(ConfigValidator::validate_database_config(&config).is_err());
    }

    #[test]
    fn test_weak_jwt_secret() {
        let mut config = create_test_config();
        config.jwt_secret = "short".to_string();
        assert!(ConfigValidator::validate_jwt_config(&config).is_err());
    }

    #[test]
    fn test_invalid_email() {
        let mut config = create_test_config();
        config.smtp_from_address = "invalid-email".to_string();
        assert!(ConfigValidator::validate_email_config(&config).is_err());
    }

    #[test]
    fn test_invalid_s3_bucket_name() {
        assert!(!ConfigValidator::is_valid_s3_bucket_name("Invalid-Bucket-Name"));
        assert!(!ConfigValidator::is_valid_s3_bucket_name("a..b"));
        assert!(!ConfigValidator::is_valid_s3_bucket_name("192.168.1.1"));
        assert!(ConfigValidator::is_valid_s3_bucket_name("valid-bucket-name"));
    }
}
