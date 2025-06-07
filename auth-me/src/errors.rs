use axum::{ http::StatusCode, response::{ IntoResponse, Response }, Json };
use std::fmt;
use serde::{ Serialize, Deserialize };

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
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
    UsernameExists,
    EmailExists,
    UserNotFound,
    UserNoLongerExists,
    InvalidHashFormat,
    HashingError,
    InvalidFromEmailFormat,
    InvalidRecipientEmailFormat,
    ExceededMaxPasswordLength(usize),
    DeleteUserError,
    UserCreationError,
    UserUpdateError,
    NotFound,
    EmailVerificationError,
    EmailNotFoundError,
    EmailPasswordError,
    PasswordComparison,
    VerificationTokenExpiredError,
    VerificationTokenInvalidError,
    VerificationTokenUnavailableError,
}

impl ToString for ErrorMessage {
    fn to_string(&self) -> String {
        self.to_str().to_owned()
    }
}

impl ErrorMessage {
    fn to_str(&self) -> String {
        match self {
            ErrorMessage::DatabaseError => "Error connecting to the database".to_string(),
            ErrorMessage::DeleteUserError => "Unable to delete the user".to_string(),
            ErrorMessage::EmailExists => "User with this email already exists".to_string(),
            ErrorMessage::EmailNotFoundError => "Unable to find email".to_string(),
            ErrorMessage::EmailPasswordError => "Failed to send forgot password email".to_string(),
            ErrorMessage::EmailVerificationError => "Failed to send verification email".to_string(),
            ErrorMessage::EmptyPassword => "Password cannot be empty".to_string(),
            ErrorMessage::ExceededMaxPasswordLength(max_length) =>
                format!("Passwords must not be more than {} characters", max_length),
            ErrorMessage::HashingError => "Error occurred while hashing the password".to_string(),
            ErrorMessage::InternalServerError =>
                "Server Error. Please try again later.".to_string(),
            ErrorMessage::InvalidFromEmailFormat => "Invalid from email format".to_string(),
            ErrorMessage::InvalidRecipientEmailFormat =>
                "Invalid recipient email format".to_string(),
            ErrorMessage::InvalidHashFormat => "Invalid password hash format".to_string(),
            ErrorMessage::InvalidToken => "Authentication token is invalid or expired".to_string(),
            ErrorMessage::NotFound => "The requested resource could not be found".to_string(),
            ErrorMessage::PermissionDenied =>
                "You are not allowed to perform this action".to_string(),
            ErrorMessage::PasswordComparison => "Password comparison error".to_string(),
            ErrorMessage::TokenNotProvided =>
                "You are not logged in, please provide a token".to_string(),
            ErrorMessage::UserCreationError => "Unable to create user.".to_string(),
            ErrorMessage::UserNoLongerExists =>
                "User belonging to this id or token does not exist".to_string(),
            ErrorMessage::UserNotAuthenticated =>
                "Authentication required, please log in".to_string(),
            ErrorMessage::UserNotFound =>
                "Unable to locate user based on the id or token".to_string(),
            ErrorMessage::UsernameExists => "User with this username already exists".to_string(),
            ErrorMessage::UserUpdateError =>
                "Unable to update user: email, username, password, or name maybe incorrect format or in use OR the user id does not exist".to_string(),
            ErrorMessage::VerificationTokenExpiredError =>
                "Verification token has expired".to_string(),
            ErrorMessage::VerificationTokenInvalidError =>
                "Verification token is invalid".to_string(),
            ErrorMessage::VerificationTokenUnavailableError =>
                "No verification token available".to_string(),
            ErrorMessage::WrongCredentials =>
                "Email, username, or password is incorrect".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpError {
    pub message: String,
    pub status: StatusCode,
}

impl HttpError {
    pub fn new(message: impl Into<String>, status: StatusCode) -> Self {
        HttpError {
            message: message.into(),
            status,
        }
    }

    pub fn server_error(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    pub fn unique_constraint_validation(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::CONFLICT,
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::NOT_FOUND,
        }
    }

    pub fn validation_error(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    pub fn into_http_response(self) -> Response {
        let response = Json(ErrorResponse {
            status: "fail".to_string(),
            message: self.message.clone(),
        });

        (self.status, response).into_response()
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HttpError: message: {}, status: {}", self.message, self.status)
    }
}

impl std::error::Error for HttpError {}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        self.into_http_response()
    }
}
