use std::sync::Arc;

use axum::{ routing::{ get, patch }, Router, middleware };
use crate::{
    AppState,
    handlers::user_handlers::*,
    middleware::auth::{ auth_middleware, require_roles },
    models::UserRole,
    utils::{ reports::get_reports, settings::admin_settings },
};

pub fn create_manager_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/reports", get(get_reports))
        .route("/api/users", get(list_users))
        .route_layer(middleware::from_fn(require_roles(vec![UserRole::Manager, UserRole::Admin])))
        .layer(middleware::from_fn(auth_middleware))
}

pub fn create_admin_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/users", get(list_all_users))
        .route("/api/admin/settings", get(admin_settings))
        .route_layer(middleware::from_fn(require_roles(vec![UserRole::Admin])))
        .layer(middleware::from_fn(auth_middleware))
}
/// USER ROUTER - Main user management routes
pub fn users_handler() -> Router<Arc<AppState>> {
    Router::new()
        // Core user CRUD operations (admin only)
        .route("/users", get(get_users).post(create_user_handler))
        .route(
            "/users/{id}",
            patch(update_user_handler).get(get_user_by_id).delete(delete_user_handler)
        )
        .layer(middleware::from_fn(require_roles(vec![UserRole::Admin])))
        .layer(middleware::from_fn(auth_middleware))
        
        // Merge manager and admin API routes (these have their own auth)
        .merge(create_manager_routes())
        .merge(create_admin_routes())
}
