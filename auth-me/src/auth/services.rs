use jsonwebtoken::{ encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm };
use serde::{ Deserialize, Serialize };
use time::{ OffsetDateTime, Duration };
use uuid::Uuid;
use diesel::prelude::*;
use bcrypt::verify;
use diesel::{ PgConnection, r2d2::{ Pool, ConnectionManager } };
use crate::{ config::Config, models::User };

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Database error: {0}")] Database(#[from] diesel::result::Error),

    #[error("Password hash error: {0}")] BcryptError(#[from] bcrypt::BcryptError),

    #[error("Connection pool error: {0}")] PoolError(#[from] diesel::r2d2::PoolError),

    #[error("Token error: {0}")] Token(#[from] jsonwebtoken::errors::Error),
}

pub struct AuthService {
    access_secret: String,
    refresh_secret: String,
    pool: Pool<ConnectionManager<PgConnection>>,
    config: Config
}

impl AuthService {
      pub fn config(&self) -> &Config {
            &self.config
      }

    pub fn new(config: &Config, pool: Pool<ConnectionManager<PgConnection>>) -> Self {
        Self {
            access_secret: config.database.jwt_secret.clone(),
            refresh_secret: config.database.jwt_refresh_secret.clone(),
            pool,
            config: config.clone()
        }
    }

    pub async fn validate_credentials(
        &self,
        username_param: &str,
        password_input: &str
    ) -> Result<User, Error> {
        use crate::schema::users::dsl::*;

        let mut conn = self.pool.get()?;

        let user = users
            .filter(username.eq(username_param))
            .first::<User>(&mut conn)
            .map_err(|_| Error::InvalidCredentials)?;

        if verify(password_input, &user.password)? {
            Ok(user)
        } else {
            Err(Error::InvalidCredentials)
        }
    }

    pub fn generate_access_token(
        &self,
        user_id: &str
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = OffsetDateTime::now_utc();
        let claims = TokenClaims {
            sub: user_id.to_string(),
            exp: (now + Duration::minutes(15)).unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.access_secret.as_bytes())
        )
    }

    pub fn generate_refresh_token(
        &self,
        user_id: &str
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = OffsetDateTime::now_utc();
        let claims = TokenClaims {
            sub: user_id.to_string(),
            exp: (now + Duration::days(7)).unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.refresh_secret.as_bytes())
        )
    }

    pub fn verify_access_token(
        &self,
        token: &str
    ) -> Result<TokenClaims, jsonwebtoken::errors::Error> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(self.access_secret.as_bytes()),
            &validation
        )?;
        Ok(token_data.claims)
    }

    pub fn verify_refresh_token(
        &self,
        token: &str
    ) -> Result<TokenClaims, jsonwebtoken::errors::Error> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(self.refresh_secret.as_bytes()),
            &validation
        )?;
        Ok(token_data.claims)
    }
}
