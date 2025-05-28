use std::sync::Arc;

use axum::{
    extract::{ Query, State },
    response::IntoResponse,
    Json,
    http::{ StatusCode, header, HeaderMap },
    Extension,
};

use diesel::{ prelude::*, result::Error as DieselError };

use tower_cookies::Cookies;
use cookie::Cookie;

use serde_json::json;

use chrono::{ Utc, Duration };
use time::Duration as TimeDuration;

use tracing::{ info, error };
use validator::Validate;

use crate::{
    middleware::auth::{ AuthUser, AuthenticatedUser },
    database::DbConnExt,
    dto::{
        authentication_dtos::{
            ForgotPasswordRequest,
            LoginRequest,
            ResetPasswordRequest,
            SignupRequest,
            UserLoginResponse,
            VerifyEmailQuery,
        },
        Response,
        user_dtos::UserQuery,
    },
    email::emails::{ send_verification_email, send_welcome_email, send_forgot_password_email },
    errors::{ ErrorMessage, HttpError },
    middleware::cookies::{ get_refresh_token, remove_auth_cookies },
    models::User,
    operations::user_operations::create_user,
    utils::{ password::hash, token::* },
    AppState,
    repositories::user_repository::UserRepository,
};

pub async fn signup_handler(
    State(state): State<Arc<AppState>>,
    Json(signup_data): Json<SignupRequest>
) -> Result<impl IntoResponse, HttpError> {
    info!("Processing signup request for email: {}", signup_data.email);

    if let Err(validation_errors) = signup_data.validate() {
        return Err(HttpError::validation_error(validation_errors.to_string()));
    }

    // Hash password with argon2 before storing
    let hashed_password = match hash(signup_data.password.clone()) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Password hashing error: {:?}", e);
            return Err(HttpError::server_error("Failed to process password".to_string()));
        }
    };

    // Set verification token to expire in 1 hour
    let token_expiration = chrono::Utc::now().naive_utc() + chrono::Duration::hours(1);

    let mut conn = state.conn()?; // PooledConnection

    // Wrap in a transaction
    let user_result = conn.transaction::<User, DieselError, _>(|conn| {
        // Create user with the hashed password
        let user = UserRepository::create_user(conn, SignupRequest {
            name: signup_data.name.clone(),
            email: signup_data.email.clone(),
            username: signup_data.username.clone(),
            password: hashed_password,
            password_confirm: String::new(), // Not used in creation
            verified: signup_data.verified,
            token_expires_at: Some(token_expiration),
            terms_accepted: true, // Assuming they accepted during signup
            role: signup_data.role,
        }).map_err(|e| {
            tracing::error!("Error creating user: {}", e);
            DieselError::RollbackTransaction
        })?;

        // Send email inside the blocking context
        if let Some(token) = &user.verification_token {
            let email_str = user.email.clone();
            let username_str = user.username.clone();
            let token = token.clone();

            // Diesel transactions are sync, so block on the async send
            let result = tokio::task::block_in_place(move || {
                tokio::runtime::Handle
                    ::current()
                    .block_on(send_verification_email(&email_str, &username_str, &token))
            });

            if let Err(e) = result {
                tracing::error!("send_verification_email failed: {}", e);
                return Err(DieselError::RollbackTransaction); // triggers rollback
            }
        }

        Ok(user)
    });

    match user_result {
        Ok(_) =>
            Ok(
                Json(
                    serde_json::json!({
            "message": "User created successfully. Please verify your email."
        })
                )
            ),
        Err(DieselError::RollbackTransaction) => {
            Err(HttpError::server_error(ErrorMessage::EmailVerificationError.to_string()))
        }
        Err(e) => {
            error!("Database error: {}", e);
            Err(HttpError::server_error(ErrorMessage::UserCreationError.to_string()))
        }
    }
}

pub async fn verify_email_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<VerifyEmailQuery>
) -> Result<impl IntoResponse, HttpError> {
    // Step 1: Validate query
    query.validate().map_err(|e| HttpError::bad_request(e.to_string()))?;

    // Step 2: Get the verified user
    let user = UserRepository::get_user(
        &state.config.database.pool,
        UserQuery::Token(query.token.clone())
    )
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(|| HttpError::not_found("User not found".to_string()))?;

    // Step 3: Use repository to verify token
    UserRepository::verify_token(&state.config.database.pool, &query.token).map_err(|e| {
        match e {
            crate::config::ConfigError::NotFound =>
                HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()),
            _ => HttpError::server_error(e.to_string()),
        }
    })?;

    // Step 4: Send welcome email
    if let Err(e) = send_welcome_email(&user.email, &user.name).await {
        eprintln!("Failed to send welcome email: {}", e);
    }

    // Step 5: Generate JWT token
    let auth_service = AuthService::new(&state.config, state.config.database.pool.clone());
    let jwt = auth_service
        .generate_access_token(&user.id.to_string())
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Step 6: Set Cookie
    let cookie_duration = time::Duration::minutes(state.config.database.jwt_expires_in * 60);
    let cookie = Cookie::build(("token", jwt.clone()))
        .path("/")
        .max_age(cookie_duration)
        .http_only(true)
        .build();

    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        cookie
            .to_string()
            .parse()
            .map_err(|_| HttpError::server_error("Failed to parse cookie".to_string()))?
    );

    // Step 7: Return success with cookie header
    let response = (
        headers,
        Json(
            json!({
            "message": "Email verified successfully",
            "user_id": user.id,
        })
        ),
    );

    Ok(response)
}

// Handler that only needs user ID
pub async fn get_profile(
    Extension(auth_user): Extension<AuthUser>,
    State(state): State<Arc<AppState>>
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Can fetch additional user data here if needed
    let user_uuid = uuid::Uuid::parse_str(&auth_user.user_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let user = UserRepository::get_user(&state.config.database.pool, UserQuery::Id(user_uuid))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(
        Json(
            json!({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role.to_str(),
        "verified": user.verified
    })
        )
    )
}

// Handler for admin-only routes (has full user info already)
pub async fn list_all_users(
    Extension(authenticated_user): Extension<AuthenticatedUser>,
    State(_state): State<Arc<AppState>>
) -> Result<Json<serde_json::Value>, StatusCode> {
    // This user is guaranteed to be an Admin because of the middleware
    println!("Admin {} is listing all users", authenticated_user.user.email);

    // I could add more database queries here to get all users
    // For now, just return the admin's info as proof of concept
    Ok(
        Json(
            json!({
        "message": "Admin access granted",
        "admin": {
            "name": authenticated_user.user.name,
            "email": authenticated_user.user.email,
            "role": authenticated_user.user.role.to_str()
        }
    })
        )
    )
}

pub async fn login_handler(
    State(_state): State<Arc<AppState>>,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Json(body): Json<LoginRequest>
) -> Result<impl IntoResponse, HttpError> {
    body.validate().map_err(|e| HttpError::bad_request(e.to_string()))?;

    // Use the AuthService to validate credentials
    let user = auth_service.validate_credentials(&body.email, &body.password).await.map_err(|e| {
        match e {
            ServiceError::HttpError(http_error) => http_error,
            _ => HttpError::server_error(e.to_string()),
        }
    })?;

    // Generate tokens using AuthService
    let access_token = auth_service
        .generate_access_token(&user.id.to_string())
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let refresh_token = auth_service
        .generate_refresh_token(&user.id.to_string())
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Set up cookies
    let access_cookie_duration = TimeDuration::minutes(15); // 15 minutes for access token
    let refresh_cookie_duration = TimeDuration::days(7); // 7 days for refresh token

    // Create access token cookie
    let mut access_cookie = Cookie::new("access_token", access_token.clone());
    access_cookie.set_path("/");
    access_cookie.set_max_age(access_cookie_duration);
    access_cookie.set_http_only(true);
    access_cookie.set_same_site(cookie::SameSite::Strict);
    access_cookie.secure();

    // Create refresh token cookie
    let mut refresh_cookie = Cookie::new("refresh_token", refresh_token);
    refresh_cookie.set_path("/");
    refresh_cookie.set_max_age(refresh_cookie_duration);
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_same_site(cookie::SameSite::Strict);
    refresh_cookie.secure();

    // Create the response
    let response = Json(UserLoginResponse {
        status: "success".to_string(),
        token: access_token,
    });

    // Add cookies to the response
    let mut headers = HeaderMap::new();
    headers.append(header::SET_COOKIE, access_cookie.to_string().parse().unwrap());
    headers.append(header::SET_COOKIE, refresh_cookie.to_string().parse().unwrap());

    let mut response = response.into_response();
    response.headers_mut().extend(headers);

    Ok(response)
}

pub async fn refresh_token_handler(
    Extension(auth_service): Extension<Arc<AuthService>>,
    mut cookies: Cookies
) -> impl IntoResponse {
    let Some(refresh_token) = get_refresh_token(&cookies) else {
        return unauthorized("No refresh token found");
    };

    let user_id = match auth_service.extract_user_id_from_token(&refresh_token, true) {
        Ok(user_id) => user_id,
        Err(_) => {
            remove_auth_cookies(&mut cookies);
            return unauthorized("Invalid refresh token");
        }
    };

    // Generate new tokens
    let new_access_token = match auth_service.generate_access_token(&user_id) {
        Ok(token) => token,
        Err(_) => {
            return internal_error("Failed to generate new access token");
        }
    };

    let new_refresh_token = match auth_service.generate_refresh_token(&user_id) {
        Ok(token) => token,
        Err(_) => {
            return internal_error("Failed to generate new refresh token");
        }
    };

    // Set up cookies
    let access_cookie_duration = TimeDuration::minutes(15); // 15 minutes for access token
    let refresh_cookie_duration = TimeDuration::days(7); // 7 days for refresh token

    // Create access token cookie
    let mut access_cookie = Cookie::new("access_token", new_access_token);
    access_cookie.set_path("/");
    access_cookie.set_max_age(access_cookie_duration);
    access_cookie.set_http_only(true);
    access_cookie.set_same_site(cookie::SameSite::Strict);
    access_cookie.secure();

    // Create refresh token cookie
    let mut refresh_cookie = Cookie::new("refresh_token", new_refresh_token);
    refresh_cookie.set_path("/");
    refresh_cookie.set_max_age(refresh_cookie_duration);
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_same_site(cookie::SameSite::Strict);
    refresh_cookie.secure();

    // Add cookies
    cookies.add(access_cookie);
    cookies.add(refresh_cookie);

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

fn unauthorized(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "status": "error",
            "message": message
        })),
    )
}

fn internal_error(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "status": "error",
            "message": message
        })),
    )
}

pub async fn logout_handler(mut cookies: Cookies) -> impl IntoResponse {
    remove_auth_cookies(&mut cookies);
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

pub async fn protected_handler(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(
            json!({ 
        "message": "This is a protected route",
        "user_id": user.user_id 
    })
        ),
    )
}

pub async fn forgot_password(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordRequest>
) -> Result<impl IntoResponse, HttpError> {
    body.validate().map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = UserRepository::get_user(
        &state.config.database.pool,
        UserQuery::Email(body.email.clone())
    )
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(|| HttpError::bad_request(ErrorMessage::EmailNotFoundError.to_string()))?;

    let verification_token = uuid::Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::minutes(30)).naive_utc();

    UserRepository::add_verification_token(
        &state.config.database.pool,
        user.id,
        verification_token.clone(),
        expires_at
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    let reset_link = format!("http://localhost:5173/reset-password?token={}", &verification_token);

    let email_sent = send_forgot_password_email(&user.email, &reset_link, &user.name).await;

    if let Err(e) = email_sent {
        eprintln!("Failed to send forgot password email: {}", e);
        return Err(HttpError::server_error(ErrorMessage::EmailPasswordError.to_string()));
    }

    let response = Response {
        message: "Password reset link has been sent to your email.".to_string(),
        status: "success".to_string(),
    };

    Ok(Json(response))
}

pub async fn reset_password(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ResetPasswordRequest>
) -> Result<impl IntoResponse, HttpError> {
    body.validate().map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = UserRepository::get_user(
        &state.config.database.pool,
        UserQuery::Token(body.token.clone())
    )
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(|| HttpError::bad_request(ErrorMessage::InvalidToken.to_string()))?;

    if let Some(expires_at) = user.token_expires_at {
        if Utc::now().naive_utc() > expires_at {
            return Err(
                HttpError::bad_request(ErrorMessage::VerificationTokenExpiredError.to_string())
            );
        }
    } else {
        return Err(HttpError::bad_request(ErrorMessage::VerificationTokenInvalidError.to_string()));
    }

    let hash_password = hash(&body.new_password).map_err(|e|
        HttpError::server_error(e.to_string())
    )?;

    UserRepository::update_user_password(
        &state.config.database.pool,
        user.id,
        hash_password
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    UserRepository::verify_token(&state.config.database.pool, &body.token).map_err(|e|
        HttpError::server_error(e.to_string())
    )?;

    let response = Response {
        message: "Password has been successfully reset.".to_string(),
        status: "success".to_string(),
    };

    Ok(Json(response))
}
