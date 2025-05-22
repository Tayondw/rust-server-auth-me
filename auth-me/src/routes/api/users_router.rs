use std::sync::Arc;

use axum::{ routing::{ get, patch, post }, Router, middleware };
use crate::{
    AppState,
    handlers::{
        user_handlers::*,
        authentication_handlers::{ signup_handler, verify_email_handler },
    },
    middleware::auth::role_check,
    models::UserRole
};

// USER ROUTER
pub fn user_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/signup", post(signup_handler))
        .route("/api/auth/verify", get(verify_email_handler))
        .route("/api/users", get(get_users).post(create_user_handler))
        .layer(
            middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })
        )
        .route(
            "/api/users/{id}",
            patch(update_user_handler).get(get_user_by_id).delete(delete_user_handler)
        )
        .with_state(state)
}
