// Test utilities and integration tests

#[cfg(test)]
pub mod test_utils {
    use std::sync::Arc;
    use diesel::{
        r2d2::{ConnectionManager, Pool},
        PgConnection,
    };
    use crate::{
        config::{Config, DatabaseConfig},
        models::{User, UserRole, NewUser},
        repositories::user_repository::UserRepository,
        services::email_services::EnhancedEmailService,
        utils::password::hash,
        AppState,
    };
    use uuid::Uuid;

    pub type TestPool = Pool<ConnectionManager<PgConnection>>;

    pub async fn setup_test_app() -> Arc<AppState> {
        // Load test configuration
        let config = Config::new().await.expect("Failed to load test config");
        
        // Create mock email service for testing
        let email_service = Arc::new(
            EnhancedEmailService::from_env_memory_only().await
                .expect("Failed to create test email service")
        );

        Arc::new(AppState {
            config,
            email_service,
        })
    }

    pub fn create_test_user(pool: &TestPool, role: UserRole) -> User {
        use crate::schema::users;
        use diesel::prelude::*;

        let mut conn = pool.get().expect("Failed to get test connection");
        
        let new_user = NewUser {
            name: "Test User".to_string(),
            email: format!("test{}@example.com", Uuid::new_v4()),
            username: format!("testuser{}", Uuid::new_v4().to_string()[..8].to_string()),
            password: hash("password123").expect("Failed to hash password"),
            verified: true,
            verification_token: None,
            token_expires_at: None,
            role,
            created_by: None,
            force_password_change: false,
        };

        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(&mut conn)
            .expect("Failed to create test user")
    }

    pub fn cleanup_test_user(pool: &TestPool, user_id: Uuid) {
        use crate::schema::users::dsl::*;
        use diesel::prelude::*;

        let mut conn = pool.get().expect("Failed to get test connection");
        diesel::delete(users.filter(id.eq(user_id)))
            .execute(&mut conn)
            .expect("Failed to delete test user");
    }

    // Mock HTTP client for testing external API calls
    pub struct MockEmailService;

    impl MockEmailService {
        pub async fn send_email(&self, _to: &str, _subject: &str, _body: &str) -> Result<(), String> {
            // Mock implementation - always succeeds in tests
            Ok(())
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::test_utils::*;
    use crate::{
        dto::authentication_dtos::LoginRequest,
        repositories::user_repository::UserRepository,
        models::UserRole,
    };
    use serde_json::json;

    #[tokio::test]
    async fn test_user_creation_and_authentication() {
        let app_state = setup_test_app().await;
        let pool = &app_state.config.database.pool;

        // Create a test user
        let user = create_test_user(pool, UserRole::User);
        
        // Verify user was created correctly
        assert_eq!(user.role, UserRole::User);
        assert!(user.verified);

        // Test login functionality would go here
        // This is a basic structure - you'd need to set up actual HTTP testing

        // Cleanup
        cleanup_test_user(pool, user.id);
    }

    #[tokio::test]
    async fn test_admin_user_permissions() {
        let app_state = setup_test_app().await;
        let pool = &app_state.config.database.pool;

        // Create admin user
        let admin_user = create_test_user(pool, UserRole::Admin);
        
        // Verify admin role
        assert_eq!(admin_user.role, UserRole::Admin);

        // Test admin-specific functionality here

        // Cleanup
        cleanup_test_user(pool, admin_user.id);
    }

    #[tokio::test]
    async fn test_password_hashing() {
        use crate::utils::password::{hash, compare};

        let password = "test_password_123";
        let hashed = hash(password).expect("Failed to hash password");
        
        assert_ne!(password, hashed);
        assert!(compare(password, &hashed).expect("Failed to compare passwords"));
        assert!(!compare("wrong_password", &hashed).expect("Failed to compare passwords"));
    }

    #[tokio::test]
    async fn test_jwt_token_generation() {
        use crate::utils::token::AuthService;

        let app_state = setup_test_app().await;
        let auth_service = AuthService::new(&app_state.config, app_state.config.database.pool.clone());

        let user_id = Uuid::new_v4().to_string();
        
        // Test access token generation
        let access_token = auth_service.generate_access_token(&user_id)
            .expect("Failed to generate access token");
        assert!(!access_token.is_empty());

        // Test refresh token generation  
        let refresh_token = auth_service.generate_refresh_token(&user_id)
            .expect("Failed to generate refresh token");
        assert!(!refresh_token.is_empty());

        // Test token extraction
        let extracted_id = auth_service.extract_user_id_from_token(&access_token, false)
            .expect("Failed to extract user ID");
        assert_eq!(extracted_id, user_id);
    }
}