use std::env;
use thiserror::Error;
use diesel::{ prelude::*, PgConnection };
use diesel::r2d2::{ Pool, ConnectionManager, PoolError as R2D2Error };
use serde::Deserialize;

use crate::{ schema::users::dsl::*, models::User, dto::user_dtos::UserQuery };

pub type PgPool = Pool<ConnectionManager<PgConnection>>;

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

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Environment variable not found: {0}")] MissingEnv(#[from] env::VarError),

    #[error("Configuration error: {0}")] Other(String),
}

impl DatabaseConfig {
    /// Build from a RawDatabaseConfig (which contains loaded fields).
    pub fn from_raw(raw: RawDatabaseConfig) -> Result<Self, R2D2Error> {
        let manager = ConnectionManager::<PgConnection>::new(&raw.database_url);
        let pool = Pool::builder().build(manager)?;

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
                    ConfigError::Other(format!("Failed to parse JWT_EXPIRES_IN: {}", e))
                })?,
            jwt_refresh_expires_in: env
                ::var("JWT_REFRESH_EXPIRES_IN")?
                .parse()
                .map_err(|e| {
                    ConfigError::Other(format!("Failed to parse JWT_REFRESH_EXPIRES_IN: {}", e))
                })?,
        };

        DatabaseConfig::from_raw(raw).map_err(|e| {
            ConfigError::Other(format!("Database pool creation failed: {}", e))
        })
    }

    pub fn get_user(&self, query: UserQuery) -> Result<Option<User>, diesel::result::Error> {
        let mut conn = self.pool
            .get()
            .map_err(|e| {
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UnableToSendCommand,
                    Box::new(e.to_string())
                )
            })?;

        let result = match query {
            UserQuery::Id(user_id) =>
                users.filter(id.eq(user_id)).first::<User>(&mut conn).optional(),
            UserQuery::Email(email_str) =>
                users.filter(email.eq(email_str)).first::<User>(&mut conn).optional(),
            UserQuery::Name(name_str) =>
                users.filter(name.eq(name_str)).first::<User>(&mut conn).optional(),
            UserQuery::Username(name_str) =>
                users.filter(username.eq(name_str)).first::<User>(&mut conn).optional(),
            UserQuery::Token(token_str) =>
                users.filter(verification_token.eq(token_str)).first::<User>(&mut conn).optional(),
        };

        result
    }
}