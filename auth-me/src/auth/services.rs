use jsonwebtoken::{ encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm };
use serde::{ Deserialize, Serialize };
use time::{ OffsetDateTime, Duration };
use uuid::Uuid;
use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}

pub struct AuthService {
    access_secret: String,
    refresh_secret: String,
}

impl AuthService {
    pub fn new(config: &Config) -> Self {
        Self {
            access_secret: config.database.jwt_secret.clone(),
            refresh_secret: config.database.jwt_refresh_secret.clone(),
        }
    }

    pub fn generate_access_token(
        &self,
        user_id: &str
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now: OffsetDateTime = OffsetDateTime::now_utc();
        let claims: TokenClaims = TokenClaims {
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
        let now: OffsetDateTime = OffsetDateTime::now_utc();
        let claims: TokenClaims = TokenClaims {
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
        let validation: Validation = Validation::new(Algorithm::HS256);
        let token_data: jsonwebtoken::TokenData<TokenClaims> = decode::<TokenClaims>(
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
        let validation: Validation = Validation::new(Algorithm::HS256);
        let token_data: jsonwebtoken::TokenData<TokenClaims> = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(self.refresh_secret.as_bytes()),
            &validation
        )?;
        Ok(token_data.claims)
    }
}
