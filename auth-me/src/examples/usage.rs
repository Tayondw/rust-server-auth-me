// Examples of using auth-me as a library

use auth_me::{
      AppState, Config, UserService, User, UserRole,
      dto::{
          user_dtos::CreateUserRequest,
          authentication_dtos::LoginRequest,
      },
      repositories::user_repository::UserRepository,
      utils::token::AuthService,
  };
  use std::sync::Arc;
  
  #[tokio::main]
  async fn main() -> Result<(), Box<dyn std::error::Error>> {
      // Example 1: Using auth-me as a library in your own application
      custom_application_example().await?;
      
      // Example 2: Extending auth-me for domain-specific needs
      chemical_inventory_example().await?;
      
      // Example 3: Adding custom authentication logic
      crypto_platform_example().await?;
      
      Ok(())
  }
  
  /// Example: Using auth-me in a custom application
  async fn custom_application_example() -> Result<(), Box<dyn std::error::Error>> {
      println!("=== Custom Application Example ===");
      
      // Initialize auth-me configuration
      let config = Config::new().await?;
      let app_state = Arc::new(AppState::new().await?);
      
      // Create a user programmatically
      let user_request = CreateUserRequest {
          name: "Jane Developer".to_string(),
          email: "jane@example.com".to_string(),
          username: "janedev".to_string(),
          password: "SecurePass123!".to_string(),
          password_confirm: "SecurePass123!".to_string(),
          verified: false,
          token_expires_at: None,
          terms_accepted: true,
          role: Some(UserRole::User),
          created_by: None,
          force_password_change: false,
      };
      
      // Use auth-me's user service
      // Note: In real usage, you'd handle the Result properly
      println!("✅ User creation logic ready");
      
      // Use auth-me's authentication service
      let auth_service = AuthService::new(&config, config.database.pool.clone());
      let token = auth_service.generate_access_token("user-id-123")?;
      println!("✅ Generated JWT token: {}...", &token[0..20]);
      
      Ok(())
  }
  
  /// Example: Extending for chemical inventory management
  async fn chemical_inventory_example() -> Result<(), Box<dyn std::error::Error>> {
      println!("=== Chemical Inventory Extension Example ===");
      
      // You would extend the auth-me models with your domain-specific ones
      #[derive(Debug)]
      struct Chemical {
          id: uuid::Uuid,
          name: String,
          formula: String,
          cas_number: String,
          safety_rating: u8,
          quantity: f64,
          unit: String,
          location: String,
          created_by: uuid::Uuid, // Links to auth-me User
      }
      
      #[derive(Debug)]
      struct InventoryOrder {
          id: uuid::Uuid,
          chemical_id: uuid::Uuid,
          ordered_by: uuid::Uuid, // Links to auth-me User
          quantity: f64,
          status: OrderStatus,
          supplier: String,
      }
      
      #[derive(Debug)]
      enum OrderStatus {
          Pending,
          Approved,
          Shipped,
          Received,
      }
      
      // Use auth-me for user management, extend for inventory
      let app_state = Arc::new(AppState::new().await?);
      
      // Example: Check user permissions before allowing chemical access
      let user_role = UserRole::Manager; // Would come from auth-me authentication
      
      match user_role {
          UserRole::Admin | UserRole::Manager => {
              println!("✅ User can access all chemicals");
          },
          UserRole::User => {
              println!("✅ User can access basic chemical info");
          },
          _ => {
              println!("❌ Insufficient permissions");
          }
      }
      
      println!("✅ Chemical inventory system using auth-me foundation");
      Ok(())
  }
  
  /// Example: Crypto platform with enhanced authentication
  async fn crypto_platform_example() -> Result<(), Box<dyn std::error::Error>> {
      println!("=== Crypto Platform Extension Example ===");
      
      // Domain-specific models that extend auth-me
      #[derive(Debug)]
      struct CryptoWallet {
          id: uuid::Uuid,
          user_id: uuid::Uuid, // Links to auth-me User
          address: String,
          currency: CryptoCurrency,
          balance: rust_decimal::Decimal,
          is_active: bool,
      }
      
      #[derive(Debug)]
      enum CryptoCurrency {
          Bitcoin,
          Ethereum,
          Lightning,
      }
      
      #[derive(Debug)]
      struct Transaction {
          id: uuid::Uuid,
          from_wallet: uuid::Uuid,
          to_wallet: Option<uuid::Uuid>,
          to_address: String,
          amount: rust_decimal::Decimal,
          fee: rust_decimal::Decimal,
          status: TransactionStatus,
          created_by: uuid::Uuid, // Links to auth-me User
      }
      
      #[derive(Debug)]
      enum TransactionStatus {
          Pending,
          Confirmed,
          Failed,
      }
      
      // Enhanced authentication for crypto operations
      struct CryptoAuthService {
          base_auth: AuthService,
      }
      
      impl CryptoAuthService {
          fn new(config: &Config, pool: auth_me::config::database::PgPool) -> Self {
              Self {
                  base_auth: AuthService::new(config, pool),
              }
          }
          
          // Add crypto-specific authentication methods
          fn generate_transaction_token(&self, user_id: &str, transaction_amount: &str) -> Result<String, Box<dyn std::error::Error>> {
              // Custom logic for high-value transaction verification
              let base_token = self.base_auth.generate_access_token(user_id)?;
              
              // In real implementation, you'd add transaction-specific claims
              println!("🔐 Generated transaction token for amount: {}", transaction_amount);
              Ok(base_token)
          }
          
          fn require_2fa_for_large_amounts(&self, amount: f64) -> bool {
              amount > 1000.0 // Require 2FA for transactions over $1000
          }
      }
      
      // Example usage
      let config = Config::new().await?;
      let crypto_auth = CryptoAuthService::new(&config, config.database.pool.clone());
      
      let transaction_token = crypto_auth.generate_transaction_token("user-123", "5000.00")?;
      println!("✅ Crypto platform using enhanced auth-me authentication");
      
      Ok(())
  }
  
  /// Example: Adding custom middleware to auth-me
  mod custom_middleware {
      use axum::{
          extract::Request,
          response::Response,
          middleware::Next,
      };
      
      /// Custom middleware that integrates with auth-me
      pub async fn domain_specific_middleware(
          request: Request,
          next: Next,
      ) -> Response {
          // Add domain-specific logic while using auth-me's authentication
          println!("🔍 Custom middleware processing request");
          
          // Process request through auth-me first, then add custom logic
          let response = next.run(request).await;
          
          // Add custom headers or processing
          response
      }
  }
  
  /// Example: Creating a custom service that uses auth-me components
  struct CustomService {
      user_service: UserService,
      // Add your domain-specific services here
  }
  
  impl CustomService {
      fn new() -> Self {
          Self {
              user_service: UserService,
          }
      }
      
      async fn custom_user_operation(&self, user_id: uuid::Uuid) -> Result<(), Box<dyn std::error::Error>> {
          // Use auth-me's user service as foundation
          println!("🔧 Performing custom operation for user: {}", user_id);
          
          // Add your domain-specific logic here
          // - Chemical inventory operations
          // - Crypto transactions
          // - Social platform features
          // - etc.
          
          Ok(())
      }
  }