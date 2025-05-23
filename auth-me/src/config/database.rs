use std::{ env, time::Duration };

use thiserror::Error;
use diesel::{
    prelude::*,
    PgConnection,
    result::Error as DieselError,
    r2d2::{ Pool, ConnectionManager, PoolError as R2D2Error },
};
use serde::Deserialize;
use chrono::{ NaiveDateTime, Utc };
use uuid::Uuid;

use crate::{ schema::users::dsl::*, models::User, dto::user_dtos::UserQuery };

pub type PgPool = Pool<ConnectionManager<PgConnection>>;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Environment variable not found: {0}")] MissingEnv(#[from] env::VarError),

    #[error("Configuration error: {0}")] Config(String),

    #[error("Database error: {0}")] Diesel(#[from] DieselError),

    #[error("Connection pool error: {0}")] Pool(#[from] R2D2Error),

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
}

// Basic validation to check for empty strings or invalid numbers
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
        };

      //   env_logger::Builder
      //       ::from_env(env_logger::Env::default().default_filter_or(&raw.rust_log))
      //       .init();

        DatabaseConfig::from_raw(raw).map_err(|e| {
            ConfigError::Config(format!("Database pool creation failed: {}", e))
        })
    }

    pub fn get_user(&self, query: UserQuery) -> Result<Option<User>, ConfigError> {
        let mut conn = self.pool.get()?;

        let result = match query {
            UserQuery::Id(user_id) =>
                users.filter(id.eq(user_id)).first::<User>(&mut conn).optional()?,
            UserQuery::Email(email_str) =>
                users.filter(email.eq(email_str)).first::<User>(&mut conn).optional()?,
            UserQuery::Name(name_str) =>
                users.filter(name.eq(name_str)).first::<User>(&mut conn).optional()?,
            UserQuery::Username(name_str) =>
                users.filter(username.eq(name_str)).first::<User>(&mut conn).optional()?,
            UserQuery::Token(token_str) =>
                users.filter(verification_token.eq(token_str)).first::<User>(&mut conn).optional()?,
        };

        Ok(result)
    }

    pub fn verified_token(&self, token_str: &str) -> Result<(), ConfigError> {
        let mut conn = self.pool.get()?;

        let now = Utc::now().naive_utc();

        let target_user = users
            .filter(verification_token.eq(Some(token_str.to_string())))
            .filter(token_expires_at.gt(now))
            .first::<User>(&mut conn)
            .optional()?;

        if let Some(user) = target_user {
            diesel
                ::update(users.filter(id.eq(user.id)))
                .set((
                    verified.eq(true),
                    verification_token.eq::<Option<String>>(None),
                    token_expires_at.eq::<Option<NaiveDateTime>>(None),
                    updated_at.eq(now),
                ))
                .execute(&mut conn)?;
            Ok(())
        } else {
            Err(ConfigError::NotFound)
        }
    }

    pub fn add_verified_token(
        &self,
        user_id: Uuid,
        token: String,
        expires_at: NaiveDateTime
    ) -> Result<(), ConfigError> {
        let mut conn = self.pool.get()?;

        diesel
            ::update(users.filter(id.eq(user_id)))
            .set((
                verification_token.eq(Some(token)),
                token_expires_at.eq(Some(expires_at)),
                updated_at.eq(Utc::now().naive_utc()),
            ))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn update_user_password(
        &self,
        user_id: Uuid,
        new_hashed_password: String
    ) -> Result<(), ConfigError> {
        let mut conn = self.pool.get()?;

        diesel
            ::update(users.filter(id.eq(user_id)))
            .set((password.eq(new_hashed_password), updated_at.eq(Utc::now().naive_utc())))
            .execute(&mut conn)?;

        Ok(())
    }

    // FOR TESTING PURPOSES
    pub fn with_pool(pool: PgPool) -> Self {
        Self {
            database_url: "".into(),
            jwt_secret: "".into(),
            jwt_refresh_secret: "".into(),
            rust_log: "".into(),
            schema: "".into(),
            jwt_expires_in: 0,
            jwt_refresh_expires_in: 0,
            pool,
        }
    }
}
