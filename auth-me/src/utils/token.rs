use axum::http::StatusCode;
use chrono::{ Duration, Utc };
use jsonwebtoken::{ decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation };
use serde::{ Deserialize, Serialize };
use uuid::Uuid;
use diesel::{ PgConnection, r2d2::{ Pool, ConnectionManager }, prelude::* };

use crate::{ config::Config, models::User, errors::{ ErrorMessage, HttpError } };

// Constants for token expiration
pub const ACCESS_TOKEN_EXPIRATION: i64 = 15; // 15 minutes
pub const REFRESH_TOKEN_EXPIRATION: i64 = 10080; // 7 days (in minutes)

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)] HttpError(#[from] HttpError),

    #[error("Database error: {0}")] DatabaseError(#[from] diesel::result::Error),

    #[error("Password hash error: {0}")] BcryptError(#[from] bcrypt::BcryptError),

    #[error("Connection pool error: {0}")] PoolError(#[from] diesel::r2d2::PoolError),

    #[error("Token error: {0}")] TokenError(#[from] jsonwebtoken::errors::Error),
}

pub struct AuthService {
    access_secret: String,
    refresh_secret: String,
    pool: Pool<ConnectionManager<PgConnection>>,
}

impl AuthService {
    pub fn new(config: &Config, pool: Pool<ConnectionManager<PgConnection>>) -> Self {
        Self {
            access_secret: config.database.jwt_secret.clone(),
            refresh_secret: config.database.jwt_refresh_secret.clone(),
            pool,
        }
    }

    pub fn get_access_secret(&self) -> &[u8] {
        self.access_secret.as_bytes()
    }

    pub fn get_refresh_secret(&self) -> &[u8] {
        self.refresh_secret.as_bytes()
    }

    pub async fn validate_credentials(
        &self,
        email_param: &str,
        password_input: &str
    ) -> Result<User, ServiceError> {
        use crate::schema::users::dsl::*;

        let mut conn = self.pool.get()?;

        let user = users
            .filter(email.eq(email_param))
            .first::<User>(&mut conn)
            .map_err(|_| {
                ServiceError::HttpError(
                    HttpError::unauthorized(ErrorMessage::WrongCredentials.to_string())
                )
            })?;

        match crate::utils::password::compare(password_input, &user.password) {
            Ok(true) => Ok(user),
            Ok(false) =>
                Err(
                    ServiceError::HttpError(
                        HttpError::unauthorized(ErrorMessage::WrongCredentials.to_string())
                    )
                ),
            Err(_) =>
                Err(
                    ServiceError::HttpError(
                        HttpError::server_error(ErrorMessage::PasswordComparison.to_string())
                    )
                ),
        }
    }

    // Core token creation function
    pub fn create_token(
        &self,
        user_id: &str,
        secret: &[u8],
        expires_in_minutes: i64
    ) -> Result<String, jsonwebtoken::errors::Error> {
        if user_id.is_empty() {
            return Err(jsonwebtoken::errors::ErrorKind::InvalidSubject.into());
        }

        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let exp = (now + Duration::minutes(expires_in_minutes)).timestamp() as usize;

        let claims = TokenClaims {
            sub: user_id.to_string(),
            exp,
            iat,
            jti: Uuid::new_v4().to_string(),
        };

        encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
    }

    // Generate access token (short-lived)
    pub fn generate_access_token(
        &self,
        user_id: &str
    ) -> Result<String, jsonwebtoken::errors::Error> {
        self.create_token(user_id, self.get_access_secret(), ACCESS_TOKEN_EXPIRATION)
    }

    // Generate refresh token (long-lived)
    pub fn generate_refresh_token(
        &self,
        user_id: &str
    ) -> Result<String, jsonwebtoken::errors::Error> {
        self.create_token(user_id, self.get_refresh_secret(), REFRESH_TOKEN_EXPIRATION)
    }

    // Helper function to extract user ID from token with proper error handling
    pub fn extract_user_id_from_token(
        &self,
        token: &str,
        is_refresh: bool
    ) -> Result<String, HttpError> {
        let secret = if is_refresh { self.get_refresh_secret() } else { self.get_access_secret() };

        decode_token(token, secret)
    }
}

pub fn decode_token<T: Into<String>>(token: T, secret: &[u8]) -> Result<String, HttpError> {
    let decode: Result<
        jsonwebtoken::TokenData<TokenClaims>,
        jsonwebtoken::errors::Error
    > = decode::<TokenClaims>(
        &token.into(),
        &DecodingKey::from_secret(secret),
        &Validation::new(Algorithm::HS256)
    );

    match decode {
        Ok(token) => Ok(token.claims.sub),
        Err(_) =>
            Err(HttpError::new(ErrorMessage::InvalidToken.to_string(), StatusCode::UNAUTHORIZED)),
    }
}
