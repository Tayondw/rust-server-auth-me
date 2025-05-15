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
                        HttpError::server_error("Password comparison error".to_string())
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
        self.create_token(user_id, self.access_secret.as_bytes(), ACCESS_TOKEN_EXPIRATION)
    }

    // Generate refresh token (long-lived)
    pub fn generate_refresh_token(
        &self,
        user_id: &str
    ) -> Result<String, jsonwebtoken::errors::Error> {
        self.create_token(user_id, self.refresh_secret.as_bytes(), REFRESH_TOKEN_EXPIRATION)
    }

    // Core token verification function
    fn verify_token(
        &self,
        token: &str,
        secret: &[u8]
    ) -> Result<TokenClaims, jsonwebtoken::errors::Error> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(secret),
            &validation
        )?;
        Ok(token_data.claims)
    }

    // Verify access token
    pub fn verify_access_token(
        &self,
        token: &str
    ) -> Result<TokenClaims, jsonwebtoken::errors::Error> {
        self.verify_token(token, self.access_secret.as_bytes())
    }

    // Verify refresh token
    pub fn verify_refresh_token(
        &self,
        token: &str
    ) -> Result<TokenClaims, jsonwebtoken::errors::Error> {
        self.verify_token(token, self.refresh_secret.as_bytes())
    }

    // Helper function to extract user ID from token with proper error handling
    pub fn extract_user_id_from_token(
        &self,
        token: &str,
        is_refresh: bool
    ) -> Result<String, HttpError> {
        let result = if is_refresh {
            self.verify_refresh_token(token)
        } else {
            self.verify_access_token(token)
        };

        match result {
            Ok(claims) => Ok(claims.sub),
            Err(_) =>
                Err(
                    HttpError::new(ErrorMessage::InvalidToken.to_string(), StatusCode::UNAUTHORIZED)
                ),
        }
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
