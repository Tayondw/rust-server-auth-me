use std::sync::Arc;

use axum::{ routing::{ get, post }, Router };
use crate::{
    handlers::authentication_handlers::{ signup_handler, login_handler, verify_email_handler, forgot_password, reset_password },
    AppState,
};

pub fn auth_handler() -> Router<Arc<AppState>> {
    Router::new()
        .route("/signup", post(signup_handler))
        .route("/login", post(login_handler))
        .route("/verify", get(verify_email_handler))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
}