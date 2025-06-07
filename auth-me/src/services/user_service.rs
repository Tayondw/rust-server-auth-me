use std::sync::Arc;

use diesel::prelude::*;
use chrono::{ Utc, Duration };
use uuid::Uuid;
use validator::Validate;
use tracing::{ info, error };

use crate::{
    dto::{
        create_user_dtos::{ AdminCreateUserRequest, CreateUserParams, AdminCreateUserResponse },
        authentication_dtos::SignupRequest,
    },
    email::emails::{ send_verification_email, send_admin_created_user_email, send_welcome_email },
    models::{ User, UserRole, PendingUser, NewPendingUser },
    repositories::{
        user_repository::UserRepository,
        pending_user_repository::PendingUserRepository,
    },
    services::email_services::EnhancedEmailService,
    utils::{ password::{ hash, generate_temp_password }, token::AuthService },
    errors::{ HttpError, ErrorMessage },
    AppState,
};

pub struct UserService;

impl UserService {
    /// Create user via self-signup (requires email verification)
    pub async fn create_user_signup(
        conn: &mut PgConnection,
        signup_data: SignupRequest,
        state: &Arc<AppState>
    ) -> Result<User, HttpError> {
        info!("Processing self-signup for email: {}", signup_data.email);

        if let Err(validation_errors) = signup_data.validate() {
            return Err(HttpError::validation_error(validation_errors.to_string()));
        }

        // Hash the provided password
        let hashed_password = hash(signup_data.password.clone()).map_err(|_|
            HttpError::bad_request(ErrorMessage::HashingError.to_string())
        )?;

        // Set verification token to expire in 1 hour
        let token_expiration = Utc::now() + Duration::hours(1);

        // Create user parameters for self-signup
        let params = CreateUserParams {
            name: signup_data.name,
            email: signup_data.email.clone(),
            username: signup_data.username,
            password: hashed_password,
            verified: false, // Self-signup users must verify email
            token_expires_at: Some(token_expiration),
            role: UserRole::User, // Default role for self-signup
            created_by: None, // Self-created
            force_password_change: false, // They chose their password
        };

        // Create the user
        let user = UserRepository::create_user_unified(conn, params).map_err(|e|
            HttpError::server_error(e.to_string())
        )?;

        // Send verification email if token exists
        if let Some(token) = &user.verification_token {
            let email_str = user.email.clone();
            let username_str = user.username.clone();
            let token_str = token.clone();

            // Send verification email (handle async in blocking context)
            tokio::task
                ::block_in_place(move || {
                    tokio::runtime::Handle
                        ::current()
                        .block_on(
                            send_verification_email(
                                &state.email_service,
                                &email_str,
                                &username_str,
                                &token_str
                            )
                        )
                })
                .map_err(|_|
                    HttpError::server_error(ErrorMessage::EmailVerificationError.to_string())
                )?;
        }

        Ok(user)
    }

    /// Create pending user via self-signup (requires email verification before actual user creation)
    /// Self-signup users are ALWAYS created with User role for security
    pub async fn create_pending_user_signup(
        state: &Arc<AppState>,
        signup_data: SignupRequest,
        pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>
    ) -> Result<PendingUser, HttpError> {
        info!("Processing self-signup for email: {}", signup_data.email);

        if let Err(validation_errors) = signup_data.validate() {
            return Err(HttpError::validation_error(validation_errors.to_string()));
        }

        // SECURITY: Validate that non-admin users cannot sign up with elevated roles
        if let Some(requested_role) = &signup_data.role {
            match requested_role {
                UserRole::Admin | UserRole::Manager | UserRole::Moderator => {
                    return Err(
                        HttpError::unauthorized(
                            "Self-signup is only allowed for regular user accounts. Administrative roles must be assigned by existing administrators.".to_string()
                        )
                    );
                }
                UserRole::User => {
                    // This is fine, but we'll ignore it and force User role anyway
                }
            }
        }

        // Check if user already exists in both users and pending_users tables
        let (email_exists, username_exists) =
            PendingUserRepository::check_user_exists_comprehensive(
                pool,
                &signup_data.email,
                &signup_data.username
            ).map_err(|e| HttpError::server_error(e.to_string()))?;

        if email_exists {
            return Err(
                HttpError::unique_constraint_validation(ErrorMessage::EmailExists.to_string())
            );
        }

        if username_exists {
            return Err(
                HttpError::unique_constraint_validation(ErrorMessage::UsernameExists.to_string())
            );
        }

        // Hash the provided password
        let hashed_password = hash(signup_data.password.clone()).map_err(|_|
            HttpError::bad_request(ErrorMessage::HashingError.to_string())
        )?;

        // Generate verification token and set expiration to 24 hours
        let verification_token = AuthService::generate_verification_token();
        let token_expiration = Utc::now().naive_utc() + Duration::hours(24);

        // Create pending user data
        // SECURITY: Force role to User for all self-signups regardless of request
        let new_pending_user = NewPendingUser {
            name: signup_data.name,
            email: signup_data.email.clone(),
            username: signup_data.username.clone(),
            password: hashed_password,
            verification_token: verification_token.clone(),
            token_expires_at: token_expiration,
            role: UserRole::User, // ALWAYS User for self-signup - NEVER trust client input for roles
            created_by: None, // Self-created
            send_welcome_email: true, // Send welcome email for self-signup users
            temp_password: None, // No temp password for self-signup (they provided their own)
            has_temp_password: false, // Not using a temporary password
            force_password_change: false, // They chose their password
        };

        // Create the pending user
        let pending_user = PendingUserRepository::create_pending_user(
            pool,
            new_pending_user
        ).map_err(|e| HttpError::server_error(e.to_string()))?;

        // Send verification email
        let email_str = pending_user.email.clone();
        let username_str = pending_user.username.clone();
        let token_str = verification_token;

        tokio::task
            ::block_in_place(move || {
                tokio::runtime::Handle
                    ::current()
                    .block_on(
                        send_verification_email(
                            &state.email_service,
                            &email_str,
                            &username_str,
                            &token_str
                        )
                    )
            })
            .map_err(|_| {
                // If email fails, clean up the pending user
                let _ = PendingUserRepository::delete_pending_user(pool, pending_user.id);
                HttpError::server_error(ErrorMessage::EmailVerificationError.to_string())
            })?;

        Ok(pending_user)
    }

    /// Complete user registration from pending user
    /// This method converts a pending user to an active user after email verification
    pub async fn complete_user_registration_from_pending(
        conn: &mut PgConnection,
        pending_user: PendingUser
    ) -> Result<User, HttpError> {
        info!("Completing user registration for email: {}", pending_user.email);

        // Create user parameters from pending user data
        let params = CreateUserParams {
            name: pending_user.name.clone(),
            email: pending_user.email.clone(),
            username: pending_user.username.clone(),
            password: pending_user.password.clone(), // Already hashed
            verified: true, // User is verified upon creation from pending
            token_expires_at: None, // No verification token needed
            role: pending_user.role,
            created_by: pending_user.created_by,
            force_password_change: pending_user.force_password_change,
        };

        // Create the verified user
        let user = UserRepository::create_user_unified(conn, params).map_err(|e| {
            error!("Failed to create user from pending user {}: {}", pending_user.email, e);
            HttpError::server_error(format!("Failed to create user: {}", e))
        })?;

        info!(
            "Successfully converted pending user {} to active user {}",
            pending_user.email,
            user.id
        );
        Ok(user)
    }

    /// Send appropriate welcome email based on pending user preferences
    /// This should be called after successful user creation from pending user
    pub async fn send_post_verification_welcome_email(
        email_service: &Arc<EnhancedEmailService>,
        user: &User,
        pending_user: &PendingUser
    ) -> Result<(), HttpError> {
        info!("Sending post-verification welcome email to user: {}", user.email);

        // Determine which welcome email to send based on pending user preferences
        let email_result = if pending_user.send_welcome_email {
            // Admin requested welcome email to be sent
            if pending_user.has_temp_password {
                info!("Sending admin-created user email with credentials to: {}", user.email);
                // Send welcome email with temporary password
                send_admin_created_user_email(
                    email_service,
                    &user.email,
                    &user.name,
                    pending_user.temp_password.as_deref()
                ).await
            } else {
                info!("Sending admin-created user email without credentials to: {}", user.email);
                // Send welcome email with login link only (admin provided password)
                send_admin_created_user_email(email_service, &user.email, &user.name, None).await
            }
        } else {
            // Admin didn't request welcome email, send basic welcome
            info!("Sending basic welcome email to: {}", user.email);
            send_welcome_email(email_service, &user.email, &user.name).await
        };

        match email_result {
            Ok(_) => {
                info!("Welcome email sent successfully to: {}", user.email);
                Ok(())
            }
            Err(e) => {
                error!("Failed to send welcome email to {}: {:?}", user.email, e);
                // Don't fail the verification process if email fails
                // Just log the error and continue
                Ok(())
            }
        }
    }

    /// Create user via admin (can be pre-verified, different role)
    /// SECURITY: This method requires admin authentication and can assign roles
    pub async fn create_user_admin(
        conn: &mut PgConnection,
        admin_request: AdminCreateUserRequest,
        admin_user_id: Uuid,
        state: &Arc<AppState>
    ) -> Result<AdminCreateUserResponse, HttpError> {
        info!("Processing admin user creation for email: {}", admin_request.email);

        // SECURITY: Verify that the requesting user is actually an admin
        let admin_user = UserRepository::get_user_by_id(&state.config.database.pool, admin_user_id)
            .map_err(|e| {
                error!("Failed to get admin user {}: {}", admin_user_id, e);
                HttpError::server_error(format!("Failed to verify admin user: {}", e))
            })?
            .ok_or_else(|| {
                error!("Admin user {} not found", admin_user_id);
                HttpError::unauthorized("Admin user not found".to_string())
            })?;

        if admin_user.role != UserRole::Admin {
            error!(
                "User {} with role {:?} attempted admin user creation",
                admin_user_id,
                admin_user.role
            );
            return Err(
                HttpError::unauthorized(
                    "Only administrators can create users with assigned roles".to_string()
                )
            );
        }

        // SECURITY: Additional validation for sensitive role assignments
        match admin_request.role {
            UserRole::Admin => {
                info!(
                    "Admin {} is creating a new admin user: {}",
                    admin_user.email,
                    admin_request.email
                );
            }
            UserRole::Manager | UserRole::Moderator => {
                info!(
                    "Admin {} is creating a {} user: {}",
                    admin_user.email,
                    admin_request.role.to_str(),
                    admin_request.email
                );
            }
            UserRole::User => {
                // Regular user creation
            }
        }

        // Check if user exists with detailed error reporting
        let (email_exists, username_exists) = UserRepository::check_user_exists(
            &state.config.database.pool,
            &admin_request.email,
            &admin_request.username
        ).map_err(|e| {
            error!(
                "Failed to check user existence for email {} / username {}: {}",
                admin_request.email,
                admin_request.username,
                e
            );
            HttpError::server_error(format!("Failed to check user existence: {}", e))
        })?;

        if email_exists {
            error!("Attempted to create user with existing email: {}", admin_request.email);
            return Err(
                HttpError::unique_constraint_validation(
                    format!("Email '{}' already exists", admin_request.email)
                )
            );
        }

        if username_exists {
            error!("Attempted to create user with existing username: {}", admin_request.username);
            return Err(
                HttpError::unique_constraint_validation(
                    format!("Username '{}' already exists", admin_request.username)
                )
            );
        }

        // Determine password (provided or generated)
        let (password, is_temp_password) = match admin_request.password {
            Some(pwd) => (pwd, false),
            None => (generate_temp_password(), true),
        };

        // Hash the password
        let hashed_password = hash(password.clone()).map_err(|e| {
            error!("Failed to hash password for user {:?}: {:?}", admin_request.email, e);
            HttpError::bad_request(ErrorMessage::HashingError.to_string())
        })?;

        // NEW LOGIC: Always create pending user for email verification
        // Store the credentials and welcome email preference for after verification
        info!("Creating pending user for email verification: {}", admin_request.email);

        let verification_token = AuthService::generate_verification_token();
        let token_expiration = (Utc::now() + Duration::hours(24)).naive_utc(); // 24 hours for admin-created

        let pending_user_params = NewPendingUser {
            name: admin_request.name.clone(),
            email: admin_request.email.clone(),
            username: admin_request.username.clone(),
            password: hashed_password,
            verification_token: verification_token.clone(),
            token_expires_at: token_expiration,
            role: admin_request.role,
            created_by: Some(admin_user_id),
            // Store admin preferences for post-verification handling
            send_welcome_email: admin_request.send_welcome_email,
            temp_password: if is_temp_password {
                Some(password.clone())
            } else {
                None
            },
            has_temp_password: is_temp_password,
            force_password_change: admin_request.force_password_change || is_temp_password,
        };

        let pending_user = PendingUserRepository::create_pending_user(
            &state.config.database.pool,
            pending_user_params
        ).map_err(|e| {
            error!("Failed to create pending user for {}: {}", admin_request.email, e);
            HttpError::server_error(format!("Failed to create pending user: {}", e))
        })?;

        info!(
            "Successfully created pending user {} with ID {}",
            admin_request.email,
            pending_user.id
        );

        // Always send verification email first
        let email_result = send_verification_email(
            &state.email_service,
            &pending_user.email,
            &pending_user.username,
            &verification_token
        ).await;

        match email_result {
            Ok(_) => info!("Verification email sent successfully to: {}", pending_user.email),
            Err(e) =>
                error!("Failed to send verification email to {}: {:?}", pending_user.email, e),
        }

        // Determine response message based on admin preferences
        let response_message = if admin_request.send_welcome_email {
            if is_temp_password {
                "User created successfully. Verification email sent. Upon verification, user will receive welcome email with temporary credentials."
            } else {
                "User created successfully. Verification email sent. Upon verification, user will receive welcome email with login instructions."
            }
        } else {
            "User created successfully. Verification email sent. User must verify email before login."
        };

        Ok(AdminCreateUserResponse {
            message: response_message.to_string(),
            user_id: pending_user.id,
            temporary_password: if is_temp_password {
                Some(password)
            } else {
                None
            },
            verification_required: true,
        })
    }

    // Validate pending user token and return pending user if valid
    pub async fn validate_pending_user_token(
        pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>,
        token: &str
    ) -> Result<PendingUser, HttpError> {
        // Get pending user by token
        let pending_user = PendingUserRepository::get_pending_user_by_token(pool, token)
            .map_err(|e| HttpError::server_error(e.to_string()))?
            .ok_or_else(|| HttpError::not_found(ErrorMessage::InvalidToken.to_string()))?;

        // Check if token is expired
        let now = Utc::now().naive_utc();
        if pending_user.token_expires_at < now {
            // Clean up expired pending user
            let _ = PendingUserRepository::delete_pending_user(pool, pending_user.id);
            return Err(HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()));
        }

        Ok(pending_user)
    }

    /// Clean up pending user after successful registration
    pub async fn cleanup_pending_user(
        pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>,
        pending_user_id: Uuid
    ) -> Result<(), HttpError> {
        PendingUserRepository::delete_pending_user(pool, pending_user_id).map_err(|e|
            HttpError::server_error(e.to_string())
        )?;
        Ok(())
    }

    /// Check if user can create other users (admin/manager permissions)
    pub fn can_create_users(user_role: &UserRole) -> bool {
        matches!(user_role, UserRole::Admin | UserRole::Moderator)
    }

    /// Validate admin user creation permissions
    pub fn validate_admin_creation_permissions(
        admin_role: &UserRole,
        target_role: &UserRole
    ) -> Result<(), HttpError> {
        match admin_role {
            UserRole::Admin => Ok(()), // Admins can create any role
            UserRole::Moderator => {
                // Moderators can only create regular users
                if matches!(target_role, UserRole::User) {
                    Ok(())
                } else {
                    Err(HttpError::unauthorized(ErrorMessage::PermissionDenied.to_string()))
                }
            }
            _ => Err(HttpError::unauthorized(ErrorMessage::PermissionDenied.to_string())),
        }
    }

    /// Resend verification email for pending user
    pub async fn resend_verification_email(
        pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>,
        state: &Arc<AppState>,
        email: &str
    ) -> Result<(), HttpError> {
        // Find pending user by email
        let pending_user = PendingUserRepository::get_pending_user_by_email(pool, email)
            .map_err(|e| HttpError::server_error(e.to_string()))?
            .ok_or_else(||
                HttpError::not_found("No pending registration found for this email".to_string())
            )?;

        // Check if token is still valid (not expired)
        let now = Utc::now().naive_utc();
        if pending_user.token_expires_at < now {
            // Clean up expired pending user
            let _ = PendingUserRepository::delete_pending_user(pool, pending_user.id);
            return Err(
                HttpError::unauthorized(
                    "Registration has expired. Please sign up again.".to_string()
                )
            );
        }

        // Resend verification email
        let email_str = pending_user.email.clone();
        let username_str = pending_user.username.clone();
        let token_str = pending_user.verification_token.clone();

        tokio::task
            ::block_in_place(move || {
                tokio::runtime::Handle
                    ::current()
                    .block_on(
                        send_verification_email(
                            &state.email_service,
                            &email_str,
                            &username_str,
                            &token_str
                        )
                    )
            })
            .map_err(|_|
                HttpError::server_error(ErrorMessage::EmailVerificationError.to_string())
            )?;

        Ok(())
    }
}
