use std::sync::Arc;

use axum::{
    Router,
    routing::{ post, get },
    middleware,
    middleware::{ from_fn, Next },
    extract::Extension,
    http::Request,
    body::Body,
};
use tower_cookies::Cookies;

use crate::{
    auth::middleware::auth_middleware,
    middleware::cookies::cookie_layer,
    handlers::authentication_handlers::*,
    AppState,
    utils::token::AuthService,
};

pub fn authentication_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    // Creating the auth_service and wrapping it in an Arc for shared ownership
    let auth_service = Arc::new(AuthService::new(&state.config, state.db_pool.clone()));

    // Protected routes that require authentication
    let protected_routes = Router::new()
        .route("/protected", get(protected_handler))
        .route(
            "/refresh",
            post({
                let auth_service_clone = auth_service.clone();
                move |cookies: Cookies| {
                    refresh_token_handler(Extension(auth_service_clone.clone()), cookies)
                }
            })
        )
        .route("/logout", post(logout_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Main router, with a login route and the protected routes merged
    Router::new()
        .route("/login", post(login_handler))
        .merge(protected_routes)
        .with_state(state)
        .layer(cookie_layer())
        .layer(
            from_fn(move |mut req: Request<Body>, next: Next| {
                let auth_service = auth_service.clone(); // Clone `auth_service` here
                async move {
                    req.extensions_mut().insert(auth_service);
                    // Forward the request with the extension
                    next.run(req).await
                }
            })
        )
}
