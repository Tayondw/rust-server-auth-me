use axum::{
    extract::{ State, Extension },
    response::Response,
    middleware::Next,
    http::{ Request, StatusCode },
    body::Body,
};
use tower_cookies::Cookies;
use std::sync::Arc;
use crate::{ auth::services::AuthService, AppState };

pub async fn auth_middleware(
    cookies: Cookies,
    Extension(auth_service): Extension<Arc<AuthService>>, // Use this instead of recreating
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

// Helper function to extract access token from cookies
fn get_access_token(cookies: &Cookies) -> Option<String> {
    cookies.get("access_token").map(|c| c.value().to_string())
}

// pub async fn auth_middleware(
//     cookies: Cookies,
//     State(state): State<Arc<AppState>>,
//     request: Request<Body>,
//     next: Next
// ) -> Response {
//     let access_token = match get_access_token(&cookies) {
//         Some(token) => token,
//         None => {
//             return Response::builder()
//                 .status(StatusCode::UNAUTHORIZED)
//                 .body(Body::from("Unauthorized: No access token"))
//                 .unwrap();
//         }
//     };

//     let auth_service = AuthService::new(&state.config, state.db_pool.clone());

//     match auth_service.verify_access_token(&access_token) {
//         Ok(_) => next.run(request).await,
//         Err(_) =>
//             Response::builder()
//                 .status(StatusCode::UNAUTHORIZED)
//                 .body(Body::from("Unauthorized: Invalid token"))
//                 .unwrap(),
//     }
// }

// pub async fn auth_middleware(
//     cookies: Cookies,
//     State(auth_service): State<Arc<AuthService>>,
//     request: Request<Body>,
//     next: Next
// ) -> Response {
//     let access_token: String = match get_access_token(&cookies) {
//         Some(token) => token,
//         None => {
//             return Response::builder()
//                 .status(StatusCode::UNAUTHORIZED)
//                 .body(Body::from("Unauthorized: No access token"))
//                 .unwrap();
//         }
//     };

//     match auth_service.verify_access_token(&access_token) {
//         Ok(_claims) => next.run(request).await,
//         Err(_) =>
//             Response::builder()
//                 .status(StatusCode::UNAUTHORIZED)
//                 .body(Body::from("Unauthorized: Invalid token"))
//                 .unwrap(),
//     }
// }
