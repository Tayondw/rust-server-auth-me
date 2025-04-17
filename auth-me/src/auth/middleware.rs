use axum::{
    extract::State,
    response::Response,
    middleware::Next,
    http::{ Request, StatusCode },
    body::Body,
};
use tower_cookies::Cookies;
use std::sync::Arc;
use crate::{ auth::services::AuthService, middleware::cookies::get_access_token };

pub async fn auth_middleware(
    cookies: Cookies,
    State(auth_service): State<Arc<AuthService>>,
    request: Request<Body>,
    next: Next
) -> Response {
    let access_token = match get_access_token(&cookies) {
        Some(token) => token,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized: No access token"))
                .unwrap();
        }
    };

    match auth_service.verify_access_token(&access_token) {
        Ok(_claims) => next.run(request).await,
        Err(_) =>
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized: Invalid token"))
                .unwrap(),
    }
}
