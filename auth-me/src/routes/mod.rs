use std::sync::Arc;

use axum::{ Router, routing::get };

use crate::{ AppState, middleware::csrf::get_csrf_token };

pub mod api;
pub mod general_router;

use api::setup_complete_router;
use general_router::general_routes;

/// Main application router assembly function
pub fn create_router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        // API routes (auth, users, etc.)
        .merge(setup_complete_router(state.clone()))
        // General routes (health check, etc.)
        .merge(general_routes())

        // CSRF token route
        .route("/csrf-token", get(get_csrf_token))

    // Add any other top-level routes here
    // .merge(other_routes())
}
