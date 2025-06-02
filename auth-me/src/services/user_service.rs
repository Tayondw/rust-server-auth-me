use std::sync::Arc;

use diesel::prelude::*;
use chrono::{ Utc, Duration };
use uuid::Uuid;
use validator::Validate;
use tracing::info;

use crate::{
    dto::{
        create_user_dtos::{ AdminCreateUserRequest, CreateUserParams, AdminCreateUserResponse },
        authentication_dtos::SignupRequest,
    },
    email::emails::{ send_verification_email, send_admin_created_user_email },
    models::{ User, UserRole, PendingUser, NewPendingUser },
    repositories::{
        user_repository::UserRepository,
        pending_user_repository::PendingUserRepository,
    },
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
        _state: &Arc<AppState>
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
                        .block_on(send_verification_email(&email_str, &username_str, &token_str))
                })
                .map_err(|_|
                    HttpError::server_error(ErrorMessage::EmailVerificationError.to_string())
                )?;
        }

        Ok(user)
    }

    /// Create pending user via self-signup (requires email verification before actual user creation)
    pub async fn create_pending_user_signup(
        signup_data: SignupRequest,
        pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>
    ) -> Result<PendingUser, HttpError> {
        info!("Processing self-signup for email: {}", signup_data.email);

        if let Err(validation_errors) = signup_data.validate() {
            return Err(HttpError::validation_error(validation_errors.to_string()));
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
        let new_pending_user = NewPendingUser {
            name: signup_data.name,
            email: signup_data.email.clone(),
            username: signup_data.username.clone(),
            password: hashed_password,
            verification_token: verification_token.clone(),
            token_expires_at: token_expiration,
            role: signup_data.role,
            created_by: None, // Self-created
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
                    .block_on(send_verification_email(&email_str, &username_str, &token_str))
            })
            .map_err(|_| {
                // If email fails, clean up the pending user
                let _ = PendingUserRepository::delete_pending_user(pool, pending_user.id);
                HttpError::server_error(ErrorMessage::EmailVerificationError.to_string())
            })?;

        Ok(pending_user)
    }

    /// Complete user registration from pending user (called during email verification)
    pub async fn complete_user_registration_from_pending(
        conn: &mut PgConnection,
        pending_user: PendingUser
    ) -> Result<User, HttpError> {
        info!("Completing user registration for email: {}", pending_user.email);

        // Create user parameters from pending user data
        let params = CreateUserParams {
            name: pending_user.name,
            email: pending_user.email,
            username: pending_user.username,
            password: pending_user.password, // Already hashed
            verified: true, // User is verified upon creation from pending
            token_expires_at: None, // No verification token needed
            role: pending_user.role,
            created_by: pending_user.created_by,
            force_password_change: pending_user.force_password_change,
        };

        // Create the actual user
        let user = UserRepository::create_user_unified(conn, params).map_err(|e|
            HttpError::server_error(e.to_string())
        )?;

        Ok(user)
    }

    /// Create user via admin (can be pre-verified, different role)
    pub async fn create_user_admin(
        conn: &mut PgConnection,
        admin_request: AdminCreateUserRequest,
        admin_user_id: Uuid,
        state: &Arc<AppState>
    ) -> Result<AdminCreateUserResponse, HttpError> {
        info!("Processing admin user creation for email: {}", admin_request.email);

        // Check if user exists
        let (email_exists, username_exists) = UserRepository::check_user_exists(
            &state.config.database.pool,
            &admin_request.email,
            &admin_request.username
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

        // Determine password (provided or generated)
        let (password, is_temp_password) = match admin_request.password {
            Some(pwd) => (pwd, false),
            None => (generate_temp_password(), true),
        };

        // Hash the password
        let hashed_password = hash(password.clone()).map_err(|_|
            HttpError::bad_request(ErrorMessage::HashingError.to_string())
        )?;

        // Set token expiration if not verified
        let token_expiration = if admin_request.verified {
            None
        } else {
            Some(Utc::now() + Duration::hours(24)) // 24 hours for admin-created
        };

        // Create user parameters for admin creation
        let params = CreateUserParams {
            name: admin_request.name,
            email: admin_request.email.clone(),
            username: admin_request.username,
            password: hashed_password,
            verified: admin_request.verified,
            token_expires_at: token_expiration,
            role: admin_request.role,
            created_by: Some(admin_user_id),
            force_password_change: admin_request.force_password_change || is_temp_password,
        };

        // Create the user
        let user = UserRepository::create_user_unified(conn, params).map_err(|e|
            HttpError::server_error(e.to_string())
        )?;

        // Send appropriate email
        if admin_request.send_welcome_email {
            let email_data = if admin_request.verified {
                // User is pre-verified, send welcome with credentials
                (
                    user.email.clone(),
                    user.name.clone(),
                    if is_temp_password { Some(password.clone()) } else { None },
                )
            } else {
                // User needs to verify email, send verification email
                if let Some(token) = &user.verification_token {
                    let email_str = user.email.clone();
                    let username_str = user.username.clone();
                    let token_str = token.clone();

                    tokio::task
                        ::block_in_place(move || {
                            tokio::runtime::Handle
                                ::current()
                                .block_on(
                                    send_verification_email(&email_str, &username_str, &token_str)
                                )
                        })
                        .map_err(|_|
                            HttpError::server_error(
                                ErrorMessage::EmailVerificationError.to_string()
                            )
                        )?;
                }
                (String::new(), String::new(), None) // Skip welcome email for now
            };

            // Send welcome email for verified users
            if admin_request.verified && !email_data.0.is_empty() {
                tokio::task
                    ::block_in_place(move || {
                        tokio::runtime::Handle
                            ::current()
                            .block_on(
                                send_admin_created_user_email(
                                    &email_data.0,
                                    &email_data.1,
                                    email_data.2.as_deref()
                                )
                            )
                    })
                    .map_err(|_|
                        HttpError::server_error(ErrorMessage::EmailVerificationError.to_string())
                    )?;
            }
        }

        Ok(AdminCreateUserResponse {
            message: if admin_request.verified {
                "User created successfully and is ready to login".to_string()
            } else {
                "User created successfully. Email verification required".to_string()
            },
            user_id: user.id,
            temporary_password: if is_temp_password {
                Some(password)
            } else {
                None
            },
            verification_required: !admin_request.verified,
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
                    .block_on(send_verification_email(&email_str, &username_str, &token_str))
            })
            .map_err(|_|
                HttpError::server_error(ErrorMessage::EmailVerificationError.to_string())
            )?;

        Ok(())
    }
}
