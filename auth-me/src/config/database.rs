use std::{ env, time::Duration };

use thiserror::Error;
use diesel::{
    PgConnection,
    result::Error as DieselError,
    r2d2::{ Pool, ConnectionManager, PoolError as R2D2Error },
};
use serde::Deserialize;

pub type PgPool = Pool<ConnectionManager<PgConnection>>;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Environment variable not found: {0}")] MissingEnv(#[from] env::VarError),

    #[error("Configuration error: {0}")] Config(String),

    #[error("Database error: {0}")] Diesel(#[from] DieselError),

    #[error("Connection pool error: {0}")] Pool(#[from] R2D2Error),

    #[error("Redis error: {0}")] Redis(#[from] redis::RedisError),

    #[error("Failed to get Redis connection")] RedisError,

    #[error("Unauthorized access")]
    Unauthorized,

    #[error("Not found")]
    NotFound,

    #[error("Internal server error")] Internal(String),
}

/*
serde::Deserialize cannot be derived for types like Pool<ConnectionManager<PgConnection>>, since they do not implement Deserialize and cannot be deserialized directly from configuration files or JSON.

=== DESIGN PATTERN: Two-Phase Configuration ===

The configuration is split into two complementary structures:

1. RawDatabaseConfig: Handles deserialization from environment variables
   - Implements Deserialize for automatic parsing from config files/env
   - Contains only serializable primitive types (String, i64, u16, etc.)
   - Performs basic validation of required fields
   - Acts as an intermediate representation

2. DatabaseConfig: The final runtime configuration
   - Contains complex types like connection pools that cannot be deserialized
   - Built from RawDatabaseConfig after validation and pool creation
   - Used throughout the application for actual operations
   - Provides testing utilities and factory methods

This separation allows for:
- Clean deserialization from multiple sources (env vars, config files, etc.)
- Proper validation before expensive resource allocation
- Testability through dependency injection
- Clear separation of concerns between config loading and runtime usage
*/

/// Raw configuration structure for deserialization
///
/// This struct contains all configuration values in their primitive form,
/// suitable for deserialization from environment variables, configuration files,
/// or other external sources. It excludes complex types like connection pools
/// that cannot be directly deserialized.
///
/// # Field Categories:
/// - **Database**: Connection string and schema information
/// - **Authentication**: JWT secrets and token expiration times
/// - **Infrastructure**: Redis URL, server port, rate limiting
/// - **Email**: SMTP server configuration for notifications
/// - **Cloud Storage**: AWS S3 credentials and bucket information
/// - **Observability**: Logging configuration
#[derive(Debug, Deserialize, Clone)]
pub struct RawDatabaseConfig {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_refresh_secret: String,
    pub rust_log: String,
    pub schema: String,
    pub jwt_expires_in: i64,
    pub jwt_refresh_expires_in: i64,
    pub redis_url: String,
    pub port: u16,
    pub rate_limit_requests_per_minute: u32,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from_address: String,
    pub aws_s3_bucket_name: String,
    pub aws_s3_key: String,
    pub aws_s3_secret: String,
    pub aws_region: String,
}

/// Validation implementation for raw configuration
///
/// Performs basic checks on configuration values before they're used
/// to create expensive resources like database connection pools.
///
/// # Validation Rules:
/// - String fields must not be empty or whitespace-only
/// - Numeric fields must be positive where appropriate
/// - Critical security fields (JWT secrets) are checked for presence
///
/// # Design Philosophy:
/// This validation is intentionally basic and focuses on preventing
/// obvious misconfigurations. More sophisticated validation (URL parsing,
/// network connectivity, etc.) happens later in the initialization process.
impl RawDatabaseConfig {
    /// Validates the raw configuration for basic consistency
    ///
    /// # Returns
    /// - `Ok(())` if all validation checks pass
    /// - `Err(ConfigError::Config)` with descriptive message if validation fails
    ///
    /// # Validation Checks:
    /// - Essential connection strings are not empty
    /// - JWT secrets are present (security critical)
    /// - Token expiration times are positive
    /// - Logging configuration is present
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.database_url.trim().is_empty() {
            return Err(ConfigError::Config("DATABASE_URL cannot be empty".into()));
        }
        if self.jwt_secret.trim().is_empty() {
            return Err(ConfigError::Config("JWT_SECRET cannot be empty".into()));
        }
        if self.jwt_refresh_secret.trim().is_empty() {
            return Err(ConfigError::Config("JWT_REFRESH_SECRET cannot be empty".into()));
        }
        if self.rust_log.trim().is_empty() {
            return Err(ConfigError::Config("RUST_LOG cannot be empty".into()));
        }
        if self.schema.trim().is_empty() {
            return Err(ConfigError::Config("SCHEMA cannot be empty".into()));
        }
        if self.jwt_expires_in <= 0 {
            return Err(ConfigError::Config("JWT_EXPIRES_IN must be greater than zero".into()));
        }
        if self.jwt_refresh_expires_in <= 0 {
            return Err(
                ConfigError::Config("JWT_REFRESH_EXPIRES_IN must be greater than zero".into())
            );
        }

        Ok(())
    }
}

/// Production-ready configuration with initialized resources
///
/// This structure contains the final configuration used throughout the application,
/// including complex types like database connection pools that cannot be deserialized
/// directly from configuration files.
///
/// # Key Features:
/// - **Database Pool**: Pre-configured connection pool for efficient database access
/// - **Validation**: All values have been validated before pool creation
/// - **Testing Support**: Factory methods for unit/integration testing
/// - **Resource Management**: Handles expensive resource initialization
///
/// # Usage Pattern:
/// ```rust
/// // Production: Load from environment
/// let config = DatabaseConfig::new()?;
///
/// // Testing: Inject test dependencies
/// let config = DatabaseConfig::with_pool(test_pool);
/// ```
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    // Core application configuration (duplicated from RawDatabaseConfig)
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_refresh_secret: String,
    pub rust_log: String,
    pub schema: String,
    pub jwt_expires_in: i64,
    pub jwt_refresh_expires_in: i64,
    pub redis_url: String,
    pub port: u16,
    pub rate_limit_requests_per_minute: u32,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from_address: String,
    pub aws_s3_bucket_name: String,
    pub aws_s3_key: String,
    pub aws_s3_secret: String,
    pub aws_region: String,

    /// Database connection pool
    ///
    /// Pre-configured pool of PostgreSQL connections managed by R2D2.
    /// Provides efficient connection reuse and automatic connection management.
    ///
    /// # Pool Configuration:
    /// - **Max Size**: 15 connections (balances performance vs resource usage)
    /// - **Connection Timeout**: 5 seconds (prevents hanging requests)
    /// - **Automatic Reconnection**: Handles transient network issues
    /// - **Connection Validation**: Ensures connections are healthy before use
    pub pool: PgPool,
}

impl DatabaseConfig {
    /// Creates a DatabaseConfig from a validated RawDatabaseConfig
    ///
    /// This is the primary constructor that takes a raw configuration,
    /// validates it, and initializes expensive resources like the database pool.
    ///
    /// # Arguments
    /// * `raw` - Pre-loaded raw configuration (typically from environment variables)
    ///
    /// # Returns
    /// * `Ok(DatabaseConfig)` - Fully initialized configuration
    /// * `Err(ConfigError)` - Validation failure or pool creation error
    ///
    /// # Database Pool Configuration
    /// The pool is configured with production-ready defaults:
    /// - **15 connections**: Suitable for moderate load applications
    /// - **5 second timeout**: Prevents request hanging in high-load scenarios
    /// - **Automatic retry**: R2D2 handles transient connection failures
    ///     ///
    /// # Example
    /// ```rust
    /// let raw_config = RawDatabaseConfig { /* loaded from env */ };
    /// let config = DatabaseConfig::from_raw(raw_config)?;
    /// ```
    pub fn from_raw(raw: RawDatabaseConfig) -> Result<Self, ConfigError> {
        // Validate the raw configuration before creating expensive resources
        raw.validate()?;
        let manager = ConnectionManager::<PgConnection>::new(&raw.database_url);
        // Create the database connection manager
        // This handles the actual PostgreSQL connection logic
        let pool = Pool::builder()
            // Maximum number of connections in the pool
            // Balances performance (more connections = more parallelism) vs resource usage (each connection consumes memory)
            .max_size(15)
            // Maximum time to wait for a connection
            // Prevents requests from hanging indefinitely
            // when the pool is exhausted
            .connection_timeout(Duration::from_secs(5))
            // Create the pool, returning error if unsuccessful
            // Common failures: invalid connection string, network issues, authentication problems, database unavailable
            .build(manager)?;

        Ok(Self {
            pool,
            // Copy all fields from the raw configuration
            // This duplication allows the DatabaseConfig to be self-contained
            database_url: raw.database_url,
            jwt_secret: raw.jwt_secret,
            jwt_refresh_secret: raw.jwt_refresh_secret,
            rust_log: raw.rust_log,
            schema: raw.schema,
            jwt_expires_in: raw.jwt_expires_in,
            jwt_refresh_expires_in: raw.jwt_refresh_expires_in,
            redis_url: raw.redis_url,
            port: raw.port,
            rate_limit_requests_per_minute: raw.rate_limit_requests_per_minute,
            smtp_server: raw.smtp_server,
            smtp_port: raw.smtp_port,
            smtp_username: raw.smtp_username,
            smtp_password: raw.smtp_password,
            smtp_from_address: raw.smtp_from_address,
            aws_s3_bucket_name: raw.aws_s3_bucket_name,
            aws_s3_key: raw.aws_s3_key,
            aws_s3_secret: raw.aws_s3_secret,
            aws_region: raw.aws_region,
        })
    }

    /// Loads configuration from environment variables and initializes resources
    ///
    /// This is the main entry point for production configuration loading.
    /// It reads all required environment variables, validates them, and
    /// creates a fully initialized DatabaseConfig.
    ///
    /// # Required Environment Variables:
    /// - `DATABASE_URL`: PostgreSQL connection string
    /// - `JWT_SECRET`: Secret for access token signing
    /// - `JWT_REFRESH_SECRET`: Secret for refresh token signing
    /// - `RUST_LOG`: Logging configuration
    /// - `SCHEMA`: Database schema name
    /// - `JWT_EXPIRES_IN`: Access token expiration (seconds)
    /// - `JWT_REFRESH_EXPIRES_IN`: Refresh token expiration (seconds)
    /// - `SMTP_*`: Email server configuration
    /// - `AWS_*`: S3 storage configuration
    ///
    /// # Optional Environment Variables (with defaults):
    /// - `REDIS_URL`: Redis connection string (default: "redis://127.0.0.1:6379")
    /// - `PORT`: Server port (default: 3000)
    /// - `RATE_LIMIT_RPM`: Rate limit per minute (default: 60)
    ///
    /// # Error Handling:
    /// - Missing required variables return descriptive ConfigError::Config
    /// - Invalid numeric values return parsing errors with context
    /// - Database connection failures return ConfigError::Pool
    ///
    /// # Example
    /// ```rust
    /// // Typically called once at application startup
    /// let config = DatabaseConfig::new()
    ///     .expect("Failed to load configuration");
    /// ```
    pub fn new() -> Result<Self, ConfigError> {
        // Helper function for required environment variables
        // Provides consistent error messages for missing variables
        let get_env = |key: &str| -> Result<String, ConfigError> {
            env::var(key).map_err(|_| {
                ConfigError::Config(format!("Missing required environment variable: {}", key))
            })
        };

        // Helper function for parsing integer environment variables
        // Provides context-aware error messages for parsing failures
        let get_env_parse = |key: &str| -> Result<i64, ConfigError> {
            let val = get_env(key)?;
            val.parse().map_err(|e| {
                ConfigError::Config(format!("Failed to parse {} as integer: {}", key, e))
            })
        };

        // Helper function for parsing u16 environment variables
        // Specialized for port numbers and similar small integers
        let get_env_parse_u16 = |key: &str| -> Result<u16, ConfigError> {
            let val = get_env(key)?;
            val.parse().map_err(|e| {
                ConfigError::Config(format!("Failed to parse {} as u16: {}", key, e))
            })
        };

        // Build the raw configuration from environment variables
        let raw = RawDatabaseConfig {
            // Required database configuration
            database_url: get_env("DATABASE_URL")?,
            jwt_secret: get_env("JWT_SECRET")?,
            jwt_refresh_secret: get_env("JWT_REFRESH_SECRET")?,
            rust_log: get_env("RUST_LOG")?,
            schema: get_env("SCHEMA")?,
            jwt_expires_in: get_env_parse("JWT_EXPIRES_IN")?,
            jwt_refresh_expires_in: get_env_parse("JWT_REFRESH_EXPIRES_IN")?,

            // Optional configuration with sensible defaults
            redis_url: env
                ::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            port: env
                ::var("PORT")
                .map(|v| v.parse().unwrap_or(3000)) // Default to 3000 if parsing fails
                .unwrap_or(3000), // Default to 3000 if variable not set
            rate_limit_requests_per_minute: env
                ::var("RATE_LIMIT_RPM")
                .map(|v| v.parse().unwrap_or(60)) // Default to 60 RPM if parsing fails
                .unwrap_or(60), // Default to 60 RPM if variable not set

            // Required SMTP configuration for email functionality
            smtp_server: get_env("SMTP_SERVER")?,
            smtp_port: get_env_parse_u16("SMTP_PORT")?,
            smtp_username: get_env("SMTP_USERNAME")?,
            smtp_password: get_env("SMTP_PASSWORD")?,
            smtp_from_address: get_env("SMTP_FROM_ADDRESS")?,

            // Required AWS S3 configuration for file storage
            aws_s3_bucket_name: get_env("AWS_S3_BUCKET_NAME")?,
            aws_s3_key: get_env("AWS_S3_KEY")?,
            aws_s3_secret: get_env("AWS_S3_SECRET")?,
            aws_region: get_env("AWS_REGION")?,
        };

        // Convert the raw configuration to a final DatabaseConfig
        // This validates the configuration and initializes the database pool
        DatabaseConfig::from_raw(raw)
    }

    /// FOR TESTING PURPOSES
    pub fn with_pool(pool: PgPool) -> Self {
        Self {
            database_url: "test".into(),
            jwt_secret: "test_secret".into(),
            jwt_refresh_secret: "test_refresh_secret".into(),
            rust_log: "debug".into(),
            schema: "test_schema".into(),
            jwt_expires_in: 3600,
            jwt_refresh_expires_in: 900,
            pool,
            redis_url: "redis://127.0.0.1:6379".into(),
            port: 8080,
            rate_limit_requests_per_minute: 60,
            smtp_server: "localhost".into(),
            smtp_port: 587,
            smtp_username: "test".into(),
            smtp_password: "test".into(),
            smtp_from_address: "test@test.com".into(),
            aws_s3_bucket_name: "test-bucket".into(),
            aws_s3_key: "test-key".into(),
            aws_s3_secret: "test-secret".into(),
            aws_region: "us-east-1".into(),
        }
    }
}
