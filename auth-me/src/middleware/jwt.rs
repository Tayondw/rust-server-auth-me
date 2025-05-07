use std::sync::Arc;

use axum::{ extract::Request, response::IntoResponse, http::header, Extension, middleware::Next };
use tower_cookies::Cookies;
use serde::{ Deserialize, Serialize };

use crate::{
    AppState,
    models::User,
    utils::token::decode_token,
    errors::{ ErrorMessage, HttpError },
    dto::user_dtos::UserQuery,
};


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTAuthMiddleware {
    pub user: User,
}

pub async fn auth(
    cookies: Cookies,
    Extension(state): Extension<Arc<AppState>>,
    mut req: Request,
    next: Next
) -> Result<impl IntoResponse, HttpError> {
    let token = cookies
        .get("token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value[7..].to_owned())
                    } else {
                        None
                    }
                })
        })
        .ok_or_else(|| HttpError::unauthorized(ErrorMessage::TokenNotProvided.to_string()))?;

    let token_details = match decode_token(token, state.config.database.jwt_secret.as_bytes()) {
        Ok(token_details) => token_details,
        Err(_) => {
            return Err(HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()));
        }
    };

    let user_id: i32 = token_details
        .parse()
        .map_err(|_| HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()))?;

    let user = state.config.database
        .get_user(UserQuery::Id(user_id)) // or UserQuery::Token(token.clone())
        .map_err(|_| HttpError::unauthorized(ErrorMessage::UserNoLongerExists.to_string()))?;
    let user = user.ok_or_else(||
        HttpError::unauthorized(ErrorMessage::UserNoLongerExists.to_string())
    )?;

    req.extensions_mut().insert(JWTAuthMiddleware { user: user.clone() });

    Ok(next.run(req).await)
}
