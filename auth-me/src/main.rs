mod config;
mod models;
mod schema;
mod dto;
mod errors;
mod connection;
mod middleware;
mod email;
mod utils;
mod handlers;
mod routes;
mod repositories;
mod services;

use config::{ Config, logging::init_logging };
use connection::seed::run_initial_setup;
use errors::HttpError;
use middleware::{
    csrf::{ csrf_middleware, TokenStore },
    cors::create_cors_layer,
    cookies::cookie_layer,
    security_headers::security_headers,
};
use routes::create_router;
use services::email_services::EnhancedEmailService;

use std::{ net::SocketAddr, sync::Arc };

use axum::{ extract::Extension, middleware::from_fn, Router };
use tokio::net::TcpListener;
use dotenvy::dotenv;
use tower_http::{ cors::CorsLayer, trace::TraceLayer };
use tracing_subscriber;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub email_service: Arc<EnhancedEmailService>,
}

#[tokio::main]
async fn main() -> Result<(), HttpError> {
    // Load .env file first
    match dotenv() {
        Ok(path) => println!("Loaded .env from: {}", path.display()),
        Err(e) => {
            println!("Warning: Could not load .env file: {}. Using system environment variables.", e);
        }
    }

    init_logging();

    // Load configuration
    let config = Config::new().await.map_err(|e| {
        eprintln!("Configuration loading failed: {}", e);
        HttpError::server_error(format!("Failed to load configuration: {}", e))
    })?;

    // Initialize the email service
    let email_service = Arc::new(
        EnhancedEmailService::from_env_with_redis().await.map_err(|e|
            HttpError::server_error(format!("Failed to initialize email service: {}", e))
        )?
    );

    // Warm up the email connection pool
    email_service
        .warmup_pool(5).await
        .map_err(|e|
            HttpError::server_error(format!("Failed to warm up email connection pool: {}", e))
        )?;

    let shared_state: Arc<AppState> = Arc::new(AppState {
        config: config.clone(),
        email_service: email_service.clone(),
    });

    // Initialize tracing subscriber
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    info!("Hello from main!");

    // Run initial setup to create admin user if needed
    info!("Running initial database setup...");
    if let Err(e) = run_initial_setup() {
        tracing::warn!("Initial setup failed: {}. This may be normal if admin already exists.", e);
        // Don't panic here - the app can still run without this
    } else {
        info!("Initial setup completed successfully");
    }

    // Determine environment
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

    // Set up middleware and routes
    let cors: CorsLayer = create_cors_layer(&environment);
    let token_store: Arc<TokenStore> = Arc::new(TokenStore::new());

    let app = Router::new()
        .merge(create_router(shared_state.clone()))
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
