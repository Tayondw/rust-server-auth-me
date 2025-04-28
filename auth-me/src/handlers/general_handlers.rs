use axum::{  extract::{ Json, State }, response::IntoResponse };
use std::sync::Arc;
use crate::{ AppState, models::{ ApiResponse, TestRequest }, errors::AppError };

pub async fn test_handler(Json(req): Json<TestRequest>) -> impl IntoResponse {
    Json(ApiResponse {
        success: true,
        data: Some(req),
        message: Some("Success".to_string()),
    })
}

pub async fn error_handler() -> impl IntoResponse {
    AppError::InternalServerError.into_response()
}

pub async fn handler_404() -> impl IntoResponse {
    AppError::NotFound.into_response()
}

pub async fn root(State(_state): State<Arc<AppState>>) -> &'static str {
    "Hello, World!"
}

pub async fn health_check() -> &'static str {
    "OK"
}
