use axum::http::StatusCode;
use chrono::{ Duration, Utc };
use jsonwebtoken::{ decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation };
use serde::{ Deserialize, Serialize };

use crate::errors::{ ErrorMessage, HttpError };

// Constants for token expiration
const DEFAULT_ACCESS_TOKEN_EXPIRES: i64 = 900; // 15 minutes in seconds
const DEFAULT_REFRESH_TOKEN_EXPIRES: i64 = 604800; // 7 days in seconds

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

pub fn create_token(
    user_id: &str,
    secret: &[u8],
    expires_in_seconds: i64
) -> Result<String, jsonwebtoken::errors::Error> {
    if user_id.is_empty() {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidSubject.into());
    }

    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + Duration::minutes(expires_in_seconds)).timestamp() as usize;
    let claims = TokenClaims {
        sub: user_id.to_string(),
        iat,
        exp,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
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
