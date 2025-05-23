use std::sync::Arc;

use axum::{
    extract::Request,
    response::Response,
    middleware::Next,
    http::{ StatusCode, header },
    Extension,
};
use axum_extra::extract::{ CookieJar, cookie::Cookie };

use crate::{
    models::{ User, UserRole },
    utils::token::{ AuthService, decode_token },
    errors::{ HttpError, ErrorMessage },
    config::{ DatabaseConfig, ConfigError },
};

/// Struct to hold user ID
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
}

/// Struct for full user info after role check
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user: User, // -> user struct from model
}

pub async fn auth_middleware(
    Extension(auth_service): Extension<Arc<AuthService>>,
    mut request: Request,
    next: Next
) -> Result<Response, StatusCode> {
    // Extract token from cookies or Authorization header
    let token: String = extract_token(&request)?;

    // Decode token to get user ID using your existing function
    let user_id: String = decode_token(token, auth_service.get_access_secret()).map_err(
        |_| StatusCode::UNAUTHORIZED
    )?;

    // Add the user ID to request extensions
    request.extensions_mut().insert(AuthUser { user_id });

    // Continue with the request
    Ok(next.run(request).await)
}

pub async fn role_check_middleware(
    Extension(_auth_service): Extension<Arc<AuthService>>,
    Extension(database_config): Extension<Arc<DatabaseConfig>>,
    mut request: Request,
    next: Next,
    required_roles: Vec<UserRole>
) -> Result<Response, StatusCode> {
    // Get the authenticated user id from the previous middleware
    let auth_user: &AuthUser = request.extensions().get::<AuthUser>().ok_or(StatusCode::UNAUTHORIZED)?;

    // Fetch the full user from database using your DatabaseConfig
    let user: User = get_user_from_db(&database_config, &auth_user.user_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?; // User no longer exists

    // Check if user has required role
    if !required_roles.contains(&user.role) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Add full user info to extensions for handlers that need it
    request.extensions_mut().insert(AuthenticatedUser { user });

    Ok(next.run(request).await)
}

// Helper function to get user from database
async fn get_user_from_db(
    database_config: &DatabaseConfig,
    user_id: &str
) -> Result<Option<User>, ConfigError> {
    use crate::dto::user_dtos::UserQuery;

    // Parse user_id as UUID
    let user_uuid = uuid::Uuid
        ::parse_str(user_id)
        .map_err(|_| ConfigError::Config("Invalid user ID format".to_string()))?;

    database_config.get_user(UserQuery::Id(user_uuid))
}

fn extract_token(request: &Request) -> Result<String, StatusCode> {
    // Try cookies first
    let cookie_jar: CookieJar = CookieJar::from_headers(request.headers());
    if let Some(cookie) = cookie_jar.get("access_token") {
        return Ok(cookie.value().to_string());
    }

    // Fallback to Authorization header
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|auth_header: &header::HeaderValue| auth_header.to_str().ok())
        .and_then(|auth_value: &str| {
            if auth_value.starts_with("Bearer ") { Some(auth_value[7..].to_owned()) } else { None }
        })
        .ok_or(StatusCode::UNAUTHORIZED)
}

/// Create role-specific middleware
pub fn require_roles(
    roles: Vec<UserRole>
) -> impl (Fn(
    Extension<Arc<AuthService>>,
    Extension<Arc<DatabaseConfig>>,
    Request,
    Next
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>) +
    Clone {
    move |auth_service, database_config, request, next| {
        let roles = roles.clone();
        Box::pin(async move {
            role_check_middleware(auth_service, database_config, request, next, roles).await
        })
    }
}
