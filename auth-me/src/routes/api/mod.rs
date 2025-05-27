use std::sync::Arc;

use axum::{ Router, extract::Extension };

use crate::{ AppState, middleware::cookies::cookie_layer, utils::token::AuthService };

pub mod auth_router;
pub mod users_router;

use auth_router::auth_handler;
use users_router::users_handler;

/// Main API router assembly function
pub fn setup_complete_router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    let auth_service = Arc::new(AuthService::new(&state.config, state.config.database.pool.clone()));

    Router::new()
        // Auth routes
        .merge(auth_handler())

        // User management routes
        .merge(users_handler())

        // Add shared services and cookie layer for the entire API
        .layer(Extension(auth_service))
        .layer(Extension(Arc::new(state.config.database.clone())))
        .layer(cookie_layer())
        .with_state(state)
}
