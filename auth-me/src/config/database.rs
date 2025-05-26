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

DatabaseConfig will be split into two parts:
      - one struct for deserializing raw config values from the environment
      - another struct that includes the actual pool
*/

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
    // SMTP fields
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from_address: String,
    // AWS fields
    pub aws_s3_bucket_name: String,
    pub aws_s3_key: String,
    pub aws_s3_secret: String,
    pub aws_region: String,
}

/// Basic validation to check for empty strings or invalid numbers
impl RawDatabaseConfig {
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

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_refresh_secret: String,
    pub rust_log: String,
    pub schema: String,
    pub jwt_expires_in: i64,
    pub jwt_refresh_expires_in: i64,
    pub pool: PgPool,
    pub redis_url: String,
    pub port: u16,
    pub rate_limit_requests_per_minute: u32,
    // SMTP config
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from_address: String,
    // AWS config
    pub aws_s3_bucket_name: String,
    pub aws_s3_key: String,
    pub aws_s3_secret: String,
    pub aws_region: String,
}

impl DatabaseConfig {
    /// Build from a RawDatabaseConfig (which contains loaded fields).
    pub fn from_raw(raw: RawDatabaseConfig) -> Result<Self, ConfigError> {
        raw.validate()?;
        let manager = ConnectionManager::<PgConnection>::new(&raw.database_url);
        let pool = Pool::builder()
            .max_size(15)
            .connection_timeout(Duration::from_secs(5))
            .build(manager)?;

        Ok(Self {
            pool,
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

    /// Load from environment variables and build the config.
    pub fn new() -> Result<Self, ConfigError> {
        let raw = RawDatabaseConfig {
            database_url: env::var("DATABASE_URL")?,
            jwt_secret: env::var("JWT_SECRET")?,
            jwt_refresh_secret: env::var("JWT_REFRESH_SECRET")?,
            rust_log: env::var("RUST_LOG")?,
            schema: env::var("SCHEMA")?,
            jwt_expires_in: env
                ::var("JWT_EXPIRES_IN")?
                .parse()
                .map_err(|e| {
                    ConfigError::Config(format!("Failed to parse JWT_EXPIRES_IN: {}", e))
                })?,
            jwt_refresh_expires_in: env
                ::var("JWT_REFRESH_EXPIRES_IN")?
                .parse()
                .map_err(|e| {
                    ConfigError::Config(format!("Failed to parse JWT_REFRESH_EXPIRES_IN: {}", e))
                })?,
            redis_url: env
                ::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            port: env::var("PORT")?.parse().unwrap_or(3000),
            rate_limit_requests_per_minute: env::var("RATE_LIMIT_RPM")?.parse().unwrap_or(60),
            // SMTP config
            smtp_server: env::var("SMTP_SERVER")?,
            smtp_port: env
                ::var("SMTP_PORT")?
                .parse()
                .map_err(|e| ConfigError::Config(format!("Failed to parse SMTP_PORT: {}", e)))?,
            smtp_username: env::var("SMTP_USERNAME")?,
            smtp_password: env::var("SMTP_PASSWORD")?,
            smtp_from_address: env::var("SMTP_FROM_ADDRESS")?,
            // AWS config
            aws_s3_bucket_name: env::var("AWS_S3_BUCKET_NAME")?,
            aws_s3_key: env::var("AWS_S3_KEY")?,
            aws_s3_secret: env::var("AWS_S3_SECRET")?,
            aws_region: env::var("AWS_REGION")?,
        };

        DatabaseConfig::from_raw(raw).map_err(|e| {
            ConfigError::Config(format!("Database pool creation failed: {}", e))
        })
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
