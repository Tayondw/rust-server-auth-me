use std::sync::Arc;

use axum::{
    extract::Request,
    response::Response,
    middleware::Next,
    http::{ StatusCode, header },
    Extension,
};
use tower_cookies::Cookies;

use crate::{
    models::{ User, UserRole },
    utils::token::AuthService,
    config::{ ConfigError, DatabaseConfig },
    repositories::user_repository::UserRepository,
};

/// Struct to hold user id after token validation
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
}

/// Struct that holds authenticated user information, which gets attached to requests after role check
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: uuid::Uuid,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub verified: bool,
    pub created_by: Option<uuid::Uuid>,
}

impl From<User> for AuthenticatedUser {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            verified: user.verified,
            created_by: user.created_by,
        }
    }
}

/*
----------------------------------------------------- PURPOSE ------------------------------------------------------------------
Provide middleware functions that work together to secure API endpoints by verifying user identity and checking permissions.
*/

/// Main authentication middleware - validates token and loads user with role checking
pub async fn auth_middleware(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(database_config): Extension<Arc<DatabaseConfig>>,
    cookies: Cookies,
    mut request: Request,
    next: Next
) -> Result<Response, StatusCode> {
    // Extract token from cookies or Authorization header
    let token: String = extract_token(&request, &cookies)?;

    // Decode token to get user ID using your existing function
    let user_id: String = auth_service
        .extract_user_id_from_token(&token, false)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Fetch the full user from database
    let user = get_user_from_db(&database_config, &user_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?; // User no longer exists

    // Add the user ID to request extensions
    request.extensions_mut().insert(AuthenticatedUser::from(user));

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
    let auth_user: &AuthUser = request
        .extensions()
        .get::<AuthUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Fetch the full user from database using your DatabaseConfig
    let user: User = get_user_from_db(&database_config, &auth_user.user_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?; // User no longer exists

    // Check if user has required role
    if !required_roles.contains(&user.role) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Add full user info to extensions for handlers that need it
    request.extensions_mut().insert(AuthenticatedUser::from(user));

    Ok(next.run(request).await)
}

// Helper function to get user from database
async fn get_user_from_db(
    database_config: &Arc<DatabaseConfig>,
    user_id: &str
) -> Result<Option<User>, ConfigError> {
    use crate::dto::user_dtos::UserQuery;

    // Parse user_id as UUID
    let user_uuid = uuid::Uuid
        ::parse_str(user_id)
        .map_err(|_| ConfigError::Config("Invalid user id format".to_string()))?;

    // Get the database pool from your DatabaseConfig
    let pool = &database_config.pool;

    // Use the associated function syntax for UserRepository::get_user
    UserRepository::get_user(pool, UserQuery::Id(user_uuid))
}

fn extract_token(request: &Request, cookies: &Cookies) -> Result<String, StatusCode> {
    // Try cookies first (access_token)
    if let Some(cookie) = cookies.get("access_token") {
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
