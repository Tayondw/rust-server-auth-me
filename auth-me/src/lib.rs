// Library entry point - exposes the auth-me functionality as a reusable library

// Public modules that can be used by other applications
pub mod config;
pub mod models;
pub mod dto;
pub mod errors;
pub mod repositories;
pub mod services;
pub mod utils;
pub mod middleware;
pub mod handlers;
pub mod routes;

// Internal modules (not exposed publicly)
mod connection;
mod email;

pub mod schema;

// Re-export commonly used types for convenience
pub use config::{Config, ConfigError, DatabaseConfig};
pub use connection::seed;
pub use errors::{HttpError, ErrorMessage};
pub use models::{User, UserRole, PendingUser};
pub use services::{
    user_service::UserService,
    email_services::EnhancedEmailService,
    cache_services::CacheService,
};

// Application state type
use std::sync::Arc;
use axum::Router;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub email_service: Arc<EnhancedEmailService>,
}

impl AppState {
    /// Create a new application state with configuration
    pub async fn new() -> Result<Self, ConfigError> {
        let config = Config::new().await?;
        
        let email_service = Arc::new(
            EnhancedEmailService::from_env_with_redis().await
                .map_err(|e| ConfigError::Config(format!("Email service error: {}", e)))?
        );

        Ok(Self {
            config,
            email_service,
        })
    }

    /// Create application state for testing
    pub fn for_testing(config: Config) -> Self {
        // Use a mock email service for testing
        let email_service = Arc::new(
            // In a real implementation, you'd create a mock email service
            // For now, we'll use the memory-only version
            futures::executor::block_on(async {
                EnhancedEmailService::from_env_memory_only().await
                    .expect("Failed to create test email service")
            })
        );

        Self {
            config,
            email_service,
        }
    }
}

/// Create the complete application router
pub fn create_app(state: Arc<AppState>) -> axum::Router<Arc<AppState>> {
    routes::create_router(state)
}

/// Initialize the application with all dependencies  
pub async fn initialize_app() -> Result<Router, ConfigError> {
      config::logging::init_logging();
      
      let state = Arc::new(AppState::new().await?);
      
      state.email_service
          .warmup_pool(5).await
          .map_err(|e| ConfigError::Config(format!("Email warmup failed: {}", e)))?;
  
      // Create router and convert to Router<()> for server
      let router_with_state = create_app(state.clone());
      let router = router_with_state.with_state(state);
      
      Ok(router)
  }

// Optional: Export test utilities when testing
#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::config::DatabaseConfig;
    
    pub async fn create_test_app() -> Arc<AppState> {
        // Create test configuration
        let pool = create_test_db_pool();
        let config = Config {
            database: DatabaseConfig::with_pool(pool),
            cache: crate::config::cache::CacheConfig::new("redis://localhost:6379").unwrap(),
        };
        
        Arc::new(AppState::for_testing(config))
    }
    
    fn create_test_db_pool() -> crate::config::database::PgPool {
        use diesel::r2d2::{ConnectionManager, Pool};
        use diesel::PgConnection;
        
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://localhost/auth_me_test".to_string());
        
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        Pool::builder()
            .build(manager)
            .expect("Failed to create test database pool")
    }
}

// Integration tests
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_app_initialization() {
        // This test ensures the app can be initialized
        // Skip if no test database is available
        if std::env::var("TEST_DATABASE_URL").is_err() {
            return;
        }
        
        let app = initialize_app().await;
        assert!(app.is_ok());
    }
    
    #[tokio::test] 
    async fn test_app_state_creation() {
        let state = test_utils::create_test_app().await;
        assert!(!state.config.database.database_url.is_empty());
    }
}