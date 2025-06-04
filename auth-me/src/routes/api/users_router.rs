use std::sync::Arc;

use axum::{ routing::{ get, patch, post, delete }, Router, middleware };
use crate::{
    AppState,
    handlers::{ user_handlers::*, additional_cache_handlers::* },
    middleware::auth::{ auth_middleware, require_roles, require_admin },
    models::UserRole,
    utils::{ reports::get_reports, settings::admin_settings },
};

/// Public user endpoints (no authentication required)
pub fn public_user_routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/users/verify", post(verify_user_token))
}

/// Self-management routes (users managing their own account; authentication required)
pub fn user_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/users/me", get(get_current_user))
        .route("/api/users/me", patch(update_current_user))
        .route("/api/users/me", delete(delete_current_user))
        .route("/api/users/me/password", patch(change_current_user_password))
        .layer(middleware::from_fn(auth_middleware))
}

pub fn manager_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/manager/reports", get(get_reports))
        .route("/api/manager/users", get(list_users))
        .route_layer(middleware::from_fn(require_roles(vec![UserRole::Manager, UserRole::Admin])))
        .layer(middleware::from_fn(auth_middleware))
}

/// Admin routes (full user management)
pub fn admin_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/users", get(list_all_users)) // Full user list with sensitive data
        .route("/api/admin/users", post(admin_create_user_handler))
        .route("/api/admin/users/search", get(search_users))
        .route("/api/admin/users/advanced-search", get(advanced_search_users))
        .route("/api/admin/users/{id}", get(get_user_by_id))
        .route("/api/admin/users/{id}", patch(admin_update_user))
        .route("/api/admin/users/{id}", delete(admin_delete_user))
        .route("/api/admin/users/bulk/delete", delete(bulk_delete_users))
        .route("/api/admin/users/bulk/update-roles", patch(bulk_update_user_roles))
        .route("/api/admin/users/bulk-verify", post(bulk_verify_users))
        .route("/api/admin/users/statistics", get(get_user_statistics))
        .route("/api/admin/users/cleanup-tokens", post(cleanup_expired_tokens))
        .route("/api/admin/settings", get(admin_settings))
        .layer(middleware::from_fn(require_admin()))
        .layer(middleware::from_fn(auth_middleware))
}

/// Cache management endpoints (admin only)
pub fn cache_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/cache/statistics", get(get_cache_statistics))
        .route("/api/cache/invalidate", post(invalidate_cache_pattern))
        .route("/api/cache/cleanup", post(manual_cache_cleanup))
        .layer(middleware::from_fn(require_admin()))
        .layer(middleware::from_fn(auth_middleware))
}

/// USER ROUTER - Main user management routes
pub fn users_handler() -> Router<Arc<AppState>> {
    Router::new()
        .merge(public_user_routes())
        .merge(user_routes())
        .merge(manager_routes())
        .merge(admin_routes())
        .merge(cache_routes())
}
