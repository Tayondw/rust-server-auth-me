use std::sync::Arc;

use axum::{
    extract::Extension,
    response::Response,
    middleware::Next,
    http::{ Request, StatusCode, header },
    body::Body,
};
use tower_cookies::Cookies;

use crate::auth::services::AuthService;

pub async fn auth_middleware(
    cookies: Cookies,
    Extension(auth_service): Extension<Arc<AuthService>>,
    mut request: Request<Body>,
    next: Next
) -> Response {
    // Try cookies first, then Authorization header
    let access_token = cookies
        .get("access_token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            // Fallback to Authorization header if cookie not found
            request
                .headers()
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

    // If no token found in either place
    let access_token = match access_token {
        Some(token) => token,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized: No access token"))
                .unwrap();
        }
    };

    // Verify token and get user ID
    let user_id = match auth_service.verify_access_token(&access_token) {
        Ok(claims) => claims.sub,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized: Invalid token"))
                .unwrap();
        }
    };

    // Add the user ID to request extensions
    // This is simpler than fetching the full user, but still provides context
    request.extensions_mut().insert(AuthUser { user_id });

    // Continue with the request
    next.run(request).await
}

// Simple struct to hold user ID
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
}

// extract access token from cookies
fn get_access_token(cookies: &Cookies) -> Option<String> {
    cookies.get("access_token").map(|c| c.value().to_string())
}
