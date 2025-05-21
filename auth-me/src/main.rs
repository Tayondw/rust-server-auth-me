mod config;
mod models;
mod schema;
mod dto;
mod errors;
mod database;
mod auth;
mod middleware;
mod email;
mod utils;
mod operations;
mod handlers;
mod routes;

use std::{ net::SocketAddr, sync::Arc };

use axum::{ extract::Extension, middleware::from_fn, routing::get, Router };
use diesel::{ prelude::*, r2d2::{ ConnectionManager, Pool } };
use config::Config;
use dotenvy::dotenv;
use routes::{ api::users_router::user_routes, general_router::general_routes };
use auth::router::authentication_routes;
use tower_http::{ cors::CorsLayer, trace::TraceLayer };
use middleware::{
    csrf::{ csrf_middleware, TokenStore, get_csrf_token },
    cors::create_cors_layer,
    cookies::cookie_layer,
    security_headers::security_headers,
};
use errors::HttpError;
use tracing_subscriber;
use tracing::info;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: Pool<ConnectionManager<PgConnection>>,
    pub config: Config,
}

#[tokio::main]
async fn main() -> Result<(), HttpError> {
    dotenv().ok();
    env_logger::init();

    // Load configuration
    let config = Config::new().await.map_err(|e| {
        HttpError::server_error(format!("Failed to load configuration: {}", e))
    })?;

    // Set up database connection pool
    let manager: ConnectionManager<PgConnection> = ConnectionManager::<PgConnection>::new(
        &config.database.database_url
    );
    let pool: Pool<ConnectionManager<PgConnection>> = Pool::builder()
        .build(manager)
        .map_err(|e| HttpError::server_error(format!("Failed to create pool: {}", e)))?;

    let shared_state: Arc<AppState> = Arc::new(AppState { db_pool: pool, config: config.clone() });

    // Initialize tracing subscriber
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    info!("Hello from main!");

    // Determine environment
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

    // Set up middleware and routes
    let cors: CorsLayer = create_cors_layer(&environment);
    let token_store: Arc<TokenStore> = Arc::new(TokenStore::new());

    let app = Router::new()
        .merge(user_routes(shared_state.clone()))
        .merge(general_routes())
        .nest("/api/auth", authentication_routes(shared_state.clone()))
        .route("/csrf-token", get(get_csrf_token))
        .with_state(shared_state)
        .layer(from_fn(csrf_middleware))
        .layer(Extension(token_store))
        .layer(cors)
        .layer(cookie_layer())
        .layer(from_fn(security_headers))
        .layer(TraceLayer::new_for_http());

    // Start the server
    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Server running on http://{}", addr);

    let listener: TcpListener = TcpListener::bind(addr).await.map_err(|e|
        HttpError::server_error(format!("Failed to bind address: {}", e))
    )?;

    axum
        ::serve(listener, app.into_make_service()).await
        .map_err(|e| HttpError::server_error(format!("Server error: {}", e)))?;

    Ok(())
}
