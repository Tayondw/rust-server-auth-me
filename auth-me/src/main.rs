// Binary entry point - runs the auth-me server

use auth_me::{ initialize_app, seed::run_initial_setup };
use std::net::SocketAddr;
use tokio::net::TcpListener;
use dotenvy::dotenv;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file first
    match dotenv() {
        Ok(path) => println!("Loaded .env from: {}", path.display()),
        Err(e) => {
            println!("Warning: Could not load .env file: {}. Using system environment variables.", e);
        }
    }

    // Initialize the complete application
    let app = match initialize_app().await {
        Ok(app) => app,
        Err(e) => {
            eprintln!("Failed to initialize application: {}", e);
            std::process::exit(1); // This is fine in a match arm
        }
    };

    // Run initial setup to create admin user if needed
    info!("Running initial database setup...");
    if let Err(e) = run_initial_setup() {
        tracing::warn!("Initial setup failed: {}. This may be normal if admin already exists.", e);
    } else {
        info!("Initial setup completed successfully");
    }

    // Start the server
    let port = std::env
        ::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("🚀 Auth-Me server running on http://{}", addr);
    println!("📚 API Documentation: http://{}/health", addr);

    let listener = TcpListener::bind(addr).await.map_err(|e|
        format!("Failed to bind to address {}: {}", addr, e)
    )?;

    axum
        ::serve(listener, app.into_make_service()).await
        .map_err(|e| format!("Server error: {}", e))?;

    Ok(())
}
