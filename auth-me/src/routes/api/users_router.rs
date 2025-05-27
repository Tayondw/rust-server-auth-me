use std::sync::Arc;

use axum::{ routing::{ get, patch, post }, Router, middleware };
use crate::{
    AppState,
    handlers::{ user_handlers::*, additional_cache_handlers::* },
    middleware::auth::{ auth_middleware, require_roles },
    models::UserRole,
    utils::{ reports::get_reports, settings::admin_settings },
};

// Public user endpoints (no authentication required)
pub fn public_user_routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/users/verify", post(verify_user_token))
}

// Protected user endpoints (authentication required)
pub fn user_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/users", get(get_users).post(create_user_handler))
        .route("/api/users/search", get(search_users))
        .route("/api/users/advanced-search", get(advanced_search_users))
        .route(
            "/api/users/{id}",
            patch(update_user).get(get_user_by_id).delete(delete_user_cache_handler)
        )
        //   .layer(middleware::from_fn(require_roles(vec![UserRole::Admin])))
        .layer(middleware::from_fn(auth_middleware))
}

pub fn manager_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/reports", get(get_reports))
        .route("/api/users", get(list_users))
        .route_layer(middleware::from_fn(require_roles(vec![UserRole::Manager, UserRole::Admin])))
        .layer(middleware::from_fn(auth_middleware))
}

// Admin-only endpoints
pub fn admin_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/users", get(list_all_users))
        .route("/api/admin/users/bulk-delete", post(bulk_delete_users))
        .route("/api/admin/users/bulk-update-roles", post(bulk_update_user_roles))
        .route("/api/admin/users/bulk-verify", post(bulk_verify_users))
        .route("/api/admin/users/statistics", get(get_user_statistics))
        .route("/api/admin/users/cleanup-tokens", post(cleanup_expired_tokens))
        .route("/api/admin/settings", get(admin_settings))
        .route_layer(middleware::from_fn(require_roles(vec![UserRole::Admin])))
        .layer(middleware::from_fn(auth_middleware))
}

/// Cache management endpoints (admin only)
pub fn cache_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/cache/statistics", get(get_cache_statistics))
        .route("/api/cache/invalidate", post(invalidate_cache_pattern))
        .route("/api/cache/cleanup", post(manual_cache_cleanup))
        .route_layer(middleware::from_fn(require_roles(vec![UserRole::Admin])))
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
