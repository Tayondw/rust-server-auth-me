use axum::{ extract::{ Json, State }, response::IntoResponse };
use std::sync::Arc;
use crate::{ AppState, models::{ ApiResponse, TestRequest }, errors::{ HttpError, ErrorMessage } };

pub async fn test_handler(Json(req): Json<TestRequest>) -> impl IntoResponse {
    Json(ApiResponse {
        success: true,
        data: Some(req),
        message: Some("Success".to_string()),
    })
}

pub async fn error_handler() -> HttpError {
    HttpError::server_error(ErrorMessage::InternalServerError.to_string())
}

pub async fn handler_404() -> HttpError {
    HttpError::not_found(ErrorMessage::NotFound.to_string())
}

pub async fn root(State(_state): State<Arc<AppState>>) -> &'static str {
    "Hello, World!"
}

pub async fn health_check() -> &'static str {
    "OK"
}
