use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;
use std::{collections::HashMap, fmt};
use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Debug, Error)]
pub enum AppError {
    #[error("The requested resource couldn't be found.")]
    NotFound,

    #[error("Validation error")]
    ValidationError(HashMap<String, String>),

    #[error("Internal Server Error")]
    InternalServerError,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status_code: StatusCode = match self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AppError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let mut response_body: serde_json::Value = json!({
            "success": false,
            "message": self.to_string(),
        });

        if let AppError::ValidationError(errors) = self {
            response_body["errors"] = serde_json::to_value(errors).unwrap();
        }

        (status_code, Json(response_body)).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
      pub status: String,
      pub message: String
}

impl fmt::Display for ErrorResponse{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

#[derive(Debug, PartialEq)]
pub enum ErrorMessage {
      DatabaseError,
      InvalidToken,
      TokenNotProvided,
      PermissionDenied,
      UserNotAuthenticated,
      InternalServerError,
      WrongCredentials,
      EmptyPassword,
      EmailExists,
      UsernameExists,
      UserNoLongerExists,
      InvalidHashFormat,
      HashingError,
      InvalidEmailFormat,
      ExceededMaxPasswordLength(usize),

}