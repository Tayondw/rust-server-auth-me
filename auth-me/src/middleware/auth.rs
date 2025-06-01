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

    // Decode token to get user ID
    let user_id: String = auth_service.extract_user_id_from_token(&token, false).map_err(|e| {
        tracing::error!("Token validation failed: {}", e);
        StatusCode::UNAUTHORIZED
    })?;

    // Fetch the full user from database
    let user = get_user_from_db(&database_config, &user_id).await
        .map_err(|e| {
            tracing::error!("Database error when fetching user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("User {} no longer exists", user_id);
            StatusCode::UNAUTHORIZED
        })?;

    // Add detailed logging
    tracing::debug!(
        "Authenticated user: id={}, email={}, role={:?}, verified={}",
        user.id,
        user.email,
        user.role,
        user.verified
    );

    // Add the authenticated user to request extensions
    request.extensions_mut().insert(AuthenticatedUser::from(user));

    // Continue with the request
    Ok(next.run(request).await)
}

/// Role check middleware with optional verification requirement
pub async fn role_check_middleware(
    request: Request,
    next: Next,
    required_roles: Vec<UserRole>,
    require_verified: bool
) -> Result<Response, StatusCode> {
    // Get the authenticated user from the previous middleware
    let auth_user: &AuthenticatedUser = request
        .extensions()
        .get::<AuthenticatedUser>()
        .ok_or_else(|| {
            tracing::error!("AuthenticatedUser not found in request extensions");
            StatusCode::UNAUTHORIZED
        })?;

    // Debug logging
    tracing::info!(
        "Role check - User: {} ({}), Role: {:?}, Verified: {}, Required roles: {:?}, Require verified: {}",
        auth_user.name,
        auth_user.id,
        auth_user.role,
        auth_user.verified,
        required_roles,
        require_verified
    );

    // Check verification status if required
    if require_verified && !auth_user.verified {
        tracing::warn!(
            "Unverified user {} attempted to access endpoint requiring verification",
            auth_user.id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Check if user has required role
    if !required_roles.contains(&auth_user.role) {
        tracing::warn!(
            "User {} with role {:?} attempted to access endpoint requiring {:?}",
            auth_user.id,
            auth_user.role,
            required_roles
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // All checks passed
    tracing::debug!("Role check passed for user {}", auth_user.id);
    Ok(next.run(request).await)
}

/// Helper function to get user from database
async fn get_user_from_db(
    database_config: &Arc<DatabaseConfig>,
    user_id: &str
) -> Result<Option<User>, ConfigError> {
    use crate::dto::user_dtos::UserQuery;

    // Parse user_id as UUID
    let user_uuid = uuid::Uuid::parse_str(user_id).map_err(|e| {
        tracing::error!("Invalid UUID format for user_id {}: {}", user_id, e);
        ConfigError::Config("Invalid user id format".to_string())
    })?;

    // Get the database pool from your DatabaseConfig
    let pool = &database_config.pool;

    // Use the associated function syntax for UserRepository::get_user
    UserRepository::get_user(pool, UserQuery::Id(user_uuid))
}

fn extract_token(request: &Request, cookies: &Cookies) -> Result<String, StatusCode> {
    // Try cookies first (access_token)
    if let Some(cookie) = cookies.get("access_token") {
        tracing::debug!("Token found in cookies");
        return Ok(cookie.value().to_string());
    }

    // Fallback to Authorization header
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|auth_header: &header::HeaderValue| auth_header.to_str().ok())
        .and_then(|auth_value: &str| {
            if auth_value.starts_with("Bearer ") { 
                Some(auth_value[7..].to_owned()) 
            } else { 
                None 
            }
        });

    match token {
        Some(t) => {
            tracing::debug!("Token found in Authorization header");
            Ok(t)
        },
        None => {
            tracing::warn!("No token found in cookies or Authorization header");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Create role-specific middleware that requires verification
pub fn require_verified_roles(
    roles: Vec<UserRole>
) -> impl (Fn(
    Request,
    Next
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>) +
    Clone {
    move |request, next| {
        let roles = roles.clone();
        Box::pin(async move { 
            role_check_middleware(request, next, roles, true).await 
        })
    }
}

/// Create role-specific middleware that doesn't require verification
pub fn require_roles(
    roles: Vec<UserRole>
) -> impl (Fn(
    Request,
    Next
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>) +
    Clone {
    move |request, next| {
        let roles = roles.clone();
        Box::pin(async move { 
            role_check_middleware(request, next, roles, false).await 
        })
    }
}

/// Convenience function for admin-only endpoints
pub fn require_admin() -> impl (Fn(
    Request,
    Next
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>) +
    Clone {
    require_verified_roles(vec![UserRole::Admin])
}