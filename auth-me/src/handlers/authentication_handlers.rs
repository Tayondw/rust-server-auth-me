use axum::{
    extract::{ Query, State },
    response::{ IntoResponse, Json as AxumJson },
    Json,
    http::StatusCode,
};
use axum_macros::debug_handler;
use uuid::Uuid;
use diesel::{ prelude::*, dsl::now };
use tower_cookies::Cookies;
use serde_json::json;
use std::sync::Arc;
use tracing::{info, error, debug};
use validator::Validate;
use serde::Deserialize;
use chrono::Utc;

use crate::{
    schema::users::dsl::*,
    models::User,
    auth::services::AuthService,
    middleware::cookies::{
        get_refresh_token,
        remove_auth_cookies,
        set_access_token,
        set_refresh_token,
    },
    dto::authentication_dtos::{ LoginRequest, SignupRequest, SignupResponse, VerifyEmailQueryDto },
    errors::{ HttpError, ErrorMessage },
    AppState,
    operations::user_operations::create_user,
    email::emails::send_verification_email,
    database::DbConnExt,
};

pub async fn signup_handler(
    State(state): State<Arc<AppState>>, // This extracts the AppState
    Json(signup_data): Json<SignupRequest> // This extracts the signup data as JSON
) -> Result<impl IntoResponse, HttpError> {
    info!("Processing signup request for email: {}", signup_data.email);

    // Single validation check for the signup data
    if let Err(validation_errors) = signup_data.validate() {
        return Err(HttpError::validation_error(validation_errors.to_string()));
    }

    let mut conn = state.conn()?; // Accessing the connection pool from AppState

    match
        create_user(
            &mut conn,
            signup_data.email.clone(), // Added .clone()
            signup_data.name.clone(), // Added .clone()
            signup_data.username.clone(), // Added .clone()
            signup_data.password.clone() // Added .clone()
        )
    {
        Ok(user) => {
            info!("Successfully created user with ID: {}", user.id);

            if let Some(token) = &user.verification_token {
                let email_str: &str = user.email.as_str(); // Explicitly create &str
                let username_str: &str = user.username.as_str();
                debug!("Email to send: {}", email_str); // Add logging
                debug!("Username to send: {}", username_str);
                debug!("Token to send: {}", token);

                let result = send_verification_email(email_str, username_str, token).await;

                if let Err(e) = result {
                    error!("send_verification_email failed: {}", e);
                    return Err(e); // Propagate the error from send_verification_email
                }
            }

            Ok(
                Json(SignupResponse { // Changed AxumJson to Json
                    message: "User successfully created".to_string(),
                    user_id: user.id.to_string(),
                })
            )
        }
        Err(e) => {
            error!("Error creating user: {}", e);
            if e.to_string().contains("UNIQUE constraint failed") {
                Err(HttpError::unique_constraint_validation(ErrorMessage::UserExists.to_string()))
            } else {
                Err(HttpError::server_error(ErrorMessage::UserCreationError.to_string()))
            }
        }
    }
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    token: String,
}

pub async fn verify_email_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<VerifyQuery>
) -> Result<impl IntoResponse, HttpError> {
    let mut conn = state.conn()?;

    // Look up user by token
    let result = diesel
        ::update(users.filter(verification_token.eq(&query.token)))
        .set((
            is_verified.eq(true),
            verification_token.eq::<Option<String>>(None),
            updated_at.eq(Utc::now().naive_utc()),
        ))
        .get_result::<User>(&mut conn);

    match result {
        Ok(user) =>
            Ok(
                Json(
                    json!({
            "message": "Email verified successfully",
            "user_id": user.id
        })
                )
            ),
        Err(_) => Err(HttpError::not_found("Invalid or expired token")),
    }
}

pub async fn login_handler(
    State(auth_service): State<Arc<AuthService>>,
    cookies: Cookies,
    Json(credentials): Json<LoginRequest>
) -> impl IntoResponse {
    match auth_service.validate_credentials(&credentials.email, &credentials.password).await {
        Ok(user) => {
            let user_id = user.id.to_string();
            match auth_service.generate_access_token(&user_id) {
                Ok(access_token) => {
                    match auth_service.generate_refresh_token(&user_id) {
                        Ok(refresh_token) => {
                            set_access_token(&cookies, access_token, auth_service.config());
                            set_refresh_token(&cookies, refresh_token, auth_service.config());

                            (
                                StatusCode::OK,
                                Json(
                                    json!({
                                    "status": "success",
                                    "message": "Successfully logged in",
                                    "user": {
                                        "id": user.id,
                                        "username": user.username,
                                        "name": user.name,
                                        "email": user.email
                                    }
                                })
                                ),
                            )
                        }
                        Err(_) =>
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(
                                    json!({
                                "status": "error",
                                "message": "Failed to generate refresh token"
                            })
                                ),
                            ),
                    }
                }
                Err(_) =>
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({
                        "status": "error",
                        "message": "Failed to generate access token"
                    })
                        ),
                    ),
            }
        }
        Err(_) =>
            (
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({
                "status": "error",
                "message": "Invalid username or password"
            })
                ),
            ),
    }
}

pub async fn refresh_token_handler(
    State(auth_service): State<Arc<AuthService>>,
    cookies: Cookies
) -> impl IntoResponse {
    match get_refresh_token(&cookies) {
        Some(refresh_token) => {
            match auth_service.verify_refresh_token(&refresh_token) {
                Ok(claims) => {
                    // Generate new access token and refresh token
                    match auth_service.generate_access_token(&claims.sub) {
                        Ok(new_access_token) => {
                            match auth_service.generate_refresh_token(&claims.sub) {
                                Ok(new_refresh_token) => {
                                    // Set both new tokens in cookies
                                    set_access_token(
                                        &cookies,
                                        new_access_token,
                                        auth_service.config()
                                    );
                                    set_refresh_token(
                                        &cookies,
                                        new_refresh_token,
                                        auth_service.config()
                                    );

                                    (
                                        StatusCode::OK,
                                        Json(
                                            json!({
                                            "status": "success",
                                            "message": "Tokens refreshed successfully"
                                        })
                                        ),
                                    )
                                }
                                Err(_) =>
                                    (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        Json(
                                            json!({
                                        "status": "error",
                                        "message": "Failed to generate new refresh token"
                                    })
                                        ),
                                    ),
                            }
                        }
                        Err(_) =>
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(
                                    json!({
                                "status": "error",
                                "message": "Failed to generate new access token"
                            })
                                ),
                            ),
                    }
                }
                Err(_) => {
                    remove_auth_cookies(&cookies);
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(
                            json!({
                            "status": "error",
                            "message": "Invalid refresh token"
                        })
                        ),
                    )
                }
            }
        }
        None =>
            (
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({
                "status": "error",
                "message": "No refresh token found"
            })
                ),
            ),
    }
}

pub async fn logout_handler(cookies: Cookies) -> impl IntoResponse {
    remove_auth_cookies(&cookies);
    (
        StatusCode::OK,
        Json(
            json!({
            "status": "success",
            "message": "Successfully logged out"
        })
        ),
    )
}

// Keep the protected handler function
pub async fn protected_handler() -> impl IntoResponse {
    (axum::http::StatusCode::OK, Json(json!({ "message": "This is a protected route" })))
}
