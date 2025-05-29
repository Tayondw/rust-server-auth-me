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
    models::{ User, UserRole },
    repositories::user_repository::UserRepository,
    utils::password::{ hash, generate_temp_password },
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
        let token_expiration = Utc::now().naive_utc() + Duration::hours(1);

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
            Some(Utc::now().naive_utc() + Duration::hours(24)) // 24 hours for admin-created
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
}
