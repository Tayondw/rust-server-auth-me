use axum::{ extract::Extension, middleware::from_fn, routing::get, Router };
use diesel::prelude::*;
use diesel::r2d2::{ ConnectionManager, Pool };
use std::{ net::SocketAddr, sync::Arc };
use tower_http::{ cors::CorsLayer, trace::TraceLayer };
use dotenvy::dotenv;
use tracing::info;
use std::error::Error as StdError;
use tracing_subscriber;
use serde::Serialize;

mod config;
mod models;
mod schema;
mod database;
mod middleware;
mod auth;
mod routes;
mod errors;

use config::Config;
use middleware::{
    csrf::{ csrf_middleware, TokenStore, get_csrf_token },
    cors::create_cors_layer,
    cookies::cookie_layer,
    security_headers::security_headers,
};
use routes::{ api::{ users::user_routes, posts::post_routes }, general::general_routes };
use auth::router::authentication_routes;

pub struct AppState {
    pub db_pool: Pool<ConnectionManager<PgConnection>>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    dotenv().ok();
    env_logger::init();

    let config: Config = Config::new().await.unwrap_or_else(|e: config::database::ConfigError| {
        eprintln!("Failed to load configuration: {}", e);
        std::process::exit(1);
    });

    let manager: ConnectionManager<PgConnection> = ConnectionManager::<PgConnection>::new(
        &config.database.database_url
    );
    let pool: Pool<ConnectionManager<PgConnection>> = Pool::builder()
        .build(manager)
        .expect("Failed to create pool");
    // Clone pool for authentication service
    let authentication_pool = pool.clone();
    let shared_state: Arc<AppState> = Arc::new(AppState {
        db_pool: pool,
    });

    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();
    info!("Hello from main!");

    let environment: String = std::env
        ::var("ENVIRONMENT")
        .unwrap_or_else(|_| "development".to_string());

    let cors: CorsLayer = create_cors_layer(&environment);
    let token_store: Arc<TokenStore> = Arc::new(TokenStore::new());

    let app: Router = Router::new()
        .merge(user_routes())
        .merge(post_routes())
        .merge(general_routes())
        .nest("/auth", authentication_routes(&config, authentication_pool))
        .route("/csrf-token", get(get_csrf_token))
        .with_state(shared_state)
        .layer(from_fn(csrf_middleware))
        .layer(Extension(token_store))
        .layer(cors)
        .layer(cookie_layer())
        .layer(from_fn(security_headers))
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Server running on http://{}", addr);

    let listener: tokio::net::TcpListener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
