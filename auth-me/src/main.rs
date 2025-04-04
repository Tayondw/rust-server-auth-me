use axum::{
    extract::{ Json, State },
    http::{ HeaderName, HeaderValue, Method, StatusCode },
    middleware::from_fn,
    response::{ IntoResponse, Response },
    routing::{ get, post },
    Router,
};

use diesel::prelude::*;
use diesel::r2d2::{ ConnectionManager, Pool };
use std::{ collections::HashMap, net::SocketAddr, sync::Arc };
use serde::{ Deserialize, Serialize };
use tower_http::{ cors::CorsLayer, trace::TraceLayer };
use dotenvy::dotenv;
use tracing::{ info, error, warn, debug };
use thiserror::Error;
use std::error::Error as StdError;

mod db;
mod config;

use config::Config;

// #[macro_use]
extern crate diesel;
pub mod models;
pub mod schema;
mod middleware;

use middleware::csrf::csrf_middleware;

// Define AppState to hold shared state
// create a struct to represent the state for a web application using a PostgreSQL database connection pool
pub struct AppState {
    pub db_pool: Pool<ConnectionManager<PgConnection>>,
}

// Create a type alias for convenience
// ARC = Atomic Reference Count
// provides thread-safe access to shared data
// provides shared ownership of a value across multiple threads
// keeps track of the number of references to the data
// only deallocates the data when all references are dropped
type AppStateShare = Arc<AppState>;

#[tokio::main] // used to make main async
async fn main() -> Result<(), Box<dyn StdError>>{
    // Load .env file
    dotenv().ok();
    env_logger::init();

    // Access environment variables
    // Handle error properly
    let config = match Config::new().await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Set up connection pool
    // ConnectionManager is a wrapper around a connection pool
    // it handles PostgreSQL connections
    let manager = ConnectionManager::<PgConnection>::new(&config.database.database_url);
    let pool = Pool::builder().build(manager).expect("Failed to create pool");

    // Create shared state
    // Make the application state safely shareable across multiple threads
    // each thread has its own copy of the state
    let shared_state = Arc::new(AppState {
        db_pool: pool,
    });

    // Initialize tracing for logging
    // tracing is a framework for instrumenting applications
    // it provides a set of abstractions for logging, tracing, and metrics
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok(); // Avoids panicking if already set

    // Get environment
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

    // Set up CORS middleware
    // CORS middleware is a middleware that allows you to configure cross-origin resource sharing (CORS)
    // it allows you to specify which origins are allowed to make requests to your server
    // Enable CORS
    // Configure CORS based on environment
    let cors = if environment == "production" {
        CorsLayer::new()
            .allow_origin("https://your-production-domain.com".parse::<HeaderValue>()?)
            .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
            .allow_headers([
                HeaderName::from_static("content-type"),
                HeaderName::from_static("authorization"),
            ])
            .allow_credentials(true)
    } else {
        // Development CORS settings
        CorsLayer::new()
            .allow_origin("http://localhost:5173".parse::<HeaderValue>()?)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                HeaderName::from_static("content-type"),
                HeaderName::from_static("authorization"),
                HeaderName::from_static("x-csrf-token"),
            ])
            .allow_credentials(true)
    };

    // Build our application with routes
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .route("/test", post(test_handler))
        .route("/error", get(error_handler))
        .fallback(handler_404)
        .layer(TraceLayer::new_for_http())
        .with_state(shared_state)
        .layer(cors) // Add the CORS middleware here
        .layer(from_fn(csrf_middleware));

    // Run the server
    // socket address are made up of IP address and port
    // brackets are used to indicate that ipv4 is used
    // the port are the last 4 digits
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

// Request and Response Models
#[derive(Serialize, Deserialize)]
struct TestRequest {
    hello: String,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    message: Option<String>,
}

// Error Handling
#[derive(Debug, Error)]
enum AppError {
    #[error("The requested resource couldn't be found.")]
    NotFound,

    #[error("Validation error")] ValidationError(HashMap<String, String>),

    #[error("Internal Server Error")]
    InternalServerError,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status_code = match self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AppError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let mut response_body =
            serde_json::json!({
            "success": false,
            "message": self.to_string(),
        });

        if let AppError::ValidationError(errors) = self {
            response_body["errors"] = serde_json::to_value(errors).unwrap();
        }

        (status_code, Json(response_body)).into_response()
    }
}

// Handlers
async fn test_handler(Json(req): Json<TestRequest>) -> impl IntoResponse {
    Json(ApiResponse {
        success: true,
        data: Some(req),
        message: Some("Success".to_string()),
    })
}

async fn error_handler() -> impl IntoResponse {
    AppError::InternalServerError.into_response()
}

async fn handler_404() -> impl IntoResponse {
    AppError::NotFound.into_response()
}

// Example of a handler using state
async fn root(State(state): State<AppStateShare>) -> &'static str {
    // You can now use state.db_pool to get a connection when needed
    "Hello, World!"
}

// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}
