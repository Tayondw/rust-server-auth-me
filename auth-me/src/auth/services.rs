use jsonwebtoken::{ encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm };
use serde::{ Deserialize, Serialize };
use time::{ OffsetDateTime, Duration };
use uuid::Uuid;

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
    pub fn new() -> Self {
        Self {
            access_secret: std::env
                ::var("JWT_SECRET")
                .expect("JWT_SECRET must be set"),
            refresh_secret: std::env
                ::var("JWT_REFRESH_SECRET")
                .expect("JWT_REFRESH_SECRET must be set"),
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
