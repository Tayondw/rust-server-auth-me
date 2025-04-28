use axum::{ extract::State, response::IntoResponse, Json, http::StatusCode };
use tower_cookies::Cookies;
use serde_json::json;
use std::sync::Arc;

use crate::{
    auth::services::AuthService,
    middleware::cookies::{
        get_refresh_token,
        remove_auth_cookies,
        set_access_token,
        set_refresh_token,
    },
    dto::user_dtos::LoginRequest
};

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
