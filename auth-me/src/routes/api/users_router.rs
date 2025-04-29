use std::sync::Arc;
use axum::{ routing::{ get, patch, post }, Router };
use crate::{ AppState, handlers::{user_handlers::*, authentication_handlers::signup_handler} };

// USER ROUTER
pub fn user_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/signup", post(signup_handler))
        .route("/api/users", get(get_users).post(create_user_handler))
        .route(
            "/api/users/{id}",
            patch(update_user_handler).get(get_user_by_id).delete(delete_user_handler)
        )
}
