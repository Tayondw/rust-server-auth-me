/*
----------------------------------------------------- PURPOSE ------------------------------------------------------------------
Provide two middleware functions that work together to secure API endpoints by verifying user identity and checking permissions.
*/

use std::sync::Arc;

use axum::{
    extract::Request,
    http::{ header, StatusCode },
    middleware::Next,
    response::IntoResponse,
    Extension,
};

use axum_extra::extract::cookie::CookieJar;
use serde::{ Deserialize, Serialize };

use crate::{
    dto::user_dtos::UserQuery,
    errors::{ ErrorMessage, HttpError },
    models::{ User, UserRole },
    utils::token,
    AppState,
};

// Container that holds authenticated user information, which gets attached to requests after successful authentication.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTAuthMiddeware {
    pub user: User,
}

pub async fn auth(
    cookie_jar: CookieJar,
    Extension(state): Extension<Arc<AppState>>,
    mut req: Request,
    next: Next
) -> Result<impl IntoResponse, HttpError> {
    let cookies = cookie_jar
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
        });

    let token = cookies.ok_or_else(|| {
        HttpError::unauthorized(ErrorMessage::TokenNotProvided.to_string())
    })?;

    let token_details = match
        token::decode_token(token, state.config.database.jwt_secret.as_bytes())
    {
        Ok(token_details) => token_details,
        Err(_) => {
            return Err(HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()));
        }
    };

    let user_id = uuid::Uuid
        ::parse_str(&token_details.to_string())
        .map_err(|_| { HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()) })?;

    let user = state.config.database
        .get_user(UserQuery::Id(user_id))
        .map_err(|_| { HttpError::unauthorized(ErrorMessage::UserNoLongerExists.to_string()) })?;

    let user = user.ok_or_else(|| {
        HttpError::unauthorized(ErrorMessage::UserNoLongerExists.to_string())
    })?;

    req.extensions_mut().insert(JWTAuthMiddeware {
        user: user.clone(),
    });

    Ok(next.run(req).await)
}

pub async fn role_check(
    Extension(_state): Extension<Arc<AppState>>,
    req: Request,
    next: Next,
    required_roles: Vec<UserRole>
) -> Result<impl IntoResponse, HttpError> {
    let user = req
        .extensions()
        .get::<JWTAuthMiddeware>()
        .ok_or_else(|| {
            HttpError::unauthorized(ErrorMessage::UserNotAuthenticated.to_string())
        })?;

    if !required_roles.contains(&user.user.role) {
        return Err(
            HttpError::new(ErrorMessage::PermissionDenied.to_string(), StatusCode::FORBIDDEN)
        );
    }

    Ok(next.run(req).await)
}
