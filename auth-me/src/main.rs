use diesel::prelude::*;
use diesel::r2d2::{ self, ConnectionManager, Pool };
use dotenvy::dotenv;
use std::sync::Arc;
use tracing::{ info, error, warn, debug };

mod db;
mod config;

use config::Config;

use axum::{ routing::{ get, post }, Router, extract::State };
use std::net::SocketAddr;

#[macro_use]
extern crate diesel;
pub mod models;
pub mod schema;

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
async fn main() {
    // Load .env file
    dotenv().ok();

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
    tracing_subscriber::fmt::init();

    // Build our application with routes
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .with_state(shared_state);

    // Run the server
    // socket address are made up of IP address and port
    // brackets are used to indicate that ipv4 is used
    // the port are the last 4 digits
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Server running on https://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
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
