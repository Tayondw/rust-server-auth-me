use std::sync::Arc;

use axum::{
    extract::Extension,
    response::Response,
    middleware::Next,
    http::{ Request, StatusCode },
    body::Body,
};
use tower_cookies::Cookies;

use crate::auth::services::AuthService;

pub async fn auth_middleware(
    cookies: Cookies,
    Extension(auth_service): Extension<Arc<AuthService>>,
    request: Request<Body>,
    next: Next
) -> Response {
    // Get the access token from cookies
    let access_token = match get_access_token(&cookies) {
        Some(token) => token,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized: No access token"))
                .unwrap();
        }
    };

    // Use the injected auth_service instead of creating a new one
    match auth_service.verify_access_token(&access_token) {
        Ok(_) => next.run(request).await,
        Err(_) =>
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized: Invalid token"))
                .unwrap(),
    }
}

// extract access token from cookies
fn get_access_token(cookies: &Cookies) -> Option<String> {
    cookies.get("access_token").map(|c| c.value().to_string())
}