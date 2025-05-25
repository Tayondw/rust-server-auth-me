use std::sync::Arc;

use axum::{ Router, routing::{ post, get }, middleware };

use crate::{
    AppState,
    handlers::authentication_handlers::{
        signup_handler,
        login_handler,
        verify_email_handler,
        forgot_password,
        reset_password,
        refresh_token_handler,
        logout_handler,
        get_profile,
        protected_handler,
    },
    middleware::auth::auth_middleware,
};

pub fn create_public_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/signup", post(signup_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/verify", get(verify_email_handler))
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/reset-password", post(reset_password))
}

pub fn create_authenticated_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/refresh", post(refresh_token_handler))
        .route("/auth/logout", post(logout_handler))
        .route("/auth/profile", get(get_profile))
        .route("/auth/protected", get(protected_handler))
        .layer(middleware::from_fn(auth_middleware))
}

// Auth router assembly function
pub fn auth_handler() -> Router<Arc<AppState>> {
    Router::new().merge(create_public_routes()).merge(create_authenticated_routes())
}
