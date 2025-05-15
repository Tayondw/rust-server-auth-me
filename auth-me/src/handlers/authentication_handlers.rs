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
use serde::{ Deserialize, Serialize };

use chrono::Utc;
use time::Duration as TimeDuration;

use tracing::{ info, error };
use validator::Validate;


use crate::{
    models::User,
    AppState,
    database::DbConnExt,
    auth::middleware::AuthUser,
    utils::{ password::hash, token::* },
    middleware::cookies::{ get_refresh_token, remove_auth_cookies },
    dto::authentication_dtos::{ LoginRequest, SignupRequest, UserLoginResponse },
    operations::user_operations::create_user,
    email::emails::{ send_verification_email, send_welcome_email },
    errors::{ HttpError, ErrorMessage },
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

    let mut conn = state.conn()?; // PooledConnection

    // Wrap in a transaction
    let user_result = conn.transaction::<User, DieselError, _>(|conn| {
        // Create user with the hashed password
        let user = create_user(
            conn,
            signup_data.email.clone(),
            signup_data.name.clone(),
            signup_data.username.clone(),
            hashed_password // Use the argon2 hashed password instead of raw password
        ).map_err(|e| {
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

#[derive(Serialize, Deserialize, Validate)]
pub struct VerifyEmailQuery {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
}

pub async fn verify_email_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<VerifyEmailQuery>
) -> Result<impl IntoResponse, HttpError> {
    use crate::schema::users::dsl::*;
    use diesel::prelude::*;

    // Step 1: Validate query
    query.validate().map_err(|e| HttpError::bad_request(e.to_string()))?;

    let mut conn = state.conn()?;

    // Step 2: Look up user by token
    let user: User = users
        .filter(verification_token.eq(&query.token))
        .first::<User>(&mut conn)
        .map_err(|_| HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()))?;

    // Step 3: Mark user as verified and remove token
    let updated_user = diesel
        ::update(users.filter(id.eq(user.id)))
        .set((
            is_verified.eq(true),
            verification_token.eq::<Option<String>>(None),
            updated_at.eq(Utc::now().naive_utc()),
        ))
        .get_result::<User>(&mut conn)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Step 4: Send welcome email
    if let Err(e) = send_welcome_email(&updated_user.email, &updated_user.name).await {
        eprintln!("Failed to send welcome email: {}", e);
    }

    // Step 5: Generate JWT token
    let auth_service = AuthService::new(&state.config, state.db_pool.clone());
    let jwt = auth_service
        .generate_access_token(&updated_user.id.to_string())
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

    // 7. Return success with cookie header
    let response = (
        headers,
        Json(
            json!({
            "message": "Email verified successfully",
            "user_id": updated_user.id,
        })
        ),
    );

    Ok(response)
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
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

    let claims = match auth_service.verify_refresh_token(&refresh_token) {
        Ok(claims) => claims,
        Err(_) => {
            remove_auth_cookies(&mut cookies);
            return unauthorized("Invalid refresh token");
        }
    };

    let new_access_token = match auth_service.generate_access_token(&claims.sub) {
        Ok(token) => token,
        Err(_) => {
            return internal_error("Failed to generate new access token");
        }
    };

    let new_refresh_token = match auth_service.generate_refresh_token(&claims.sub) {
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
