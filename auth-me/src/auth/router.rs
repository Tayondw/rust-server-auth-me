use axum::{ Router, routing::{ post, get }, response::IntoResponse, Json, middleware };
use std::sync::Arc;
use serde_json::json;

use crate::{
    auth::{
        services::AuthService,
        handlers::{ login_handler, refresh_token_handler, logout_handler },
        middleware::auth_middleware,
    },
    middleware::cookies::cookie_layer,
    AppState,
};

pub fn authentication_routes() -> Router<Arc<AppState>> {
    let authentication_service = Arc::new(AuthService::new());

    // Create protected routes
    let protected_routes = Router::new()
        .route("/protected", get(protected_handler))
        .route("/refresh", post(refresh_token_handler))
        .route("/logout", post(logout_handler))
        .layer(
            middleware::from_fn_with_state(
                authentication_service.clone(),
                auth_middleware
            )
        );

    // Combine with public routes
    Router::new()
        .route("/login", post(login_handler))
        .merge(protected_routes)
        .with_state(authentication_service)
        .layer(cookie_layer())
}

// Keep the protected handler function
async fn protected_handler() -> impl IntoResponse {
    (axum::http::StatusCode::OK, Json(json!({ "message": "This is a protected route" })))
}
