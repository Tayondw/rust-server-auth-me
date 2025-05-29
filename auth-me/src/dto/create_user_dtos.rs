use serde::{ Deserialize, Serialize };
use validator::{ Validate, ValidationError };
use chrono::NaiveDateTime;

use crate::models::UserRole;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserParams {
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub verified: bool,
    pub token_expires_at: Option<NaiveDateTime>,
    pub role: UserRole,
    pub created_by: Option<uuid::Uuid>, // Track who created the user
    pub force_password_change: bool, // Force password change on first login
}

#[derive(Validate, Debug, Clone, Serialize, Deserialize)]
pub struct AdminCreateUserRequest {
    #[validate(
        length(min = 1, message = "Name is required"),
        length(max = 25, message = "Name cannot be longer than 25 characters")
    )]
    pub name: String,

    #[validate(length(min = 1, message = "Email is required"), email(message = "Email is invalid"))]
    pub email: String,

    #[validate(
        length(min = 1, message = "Username is required"),
        length(max = 25, message = "Username cannot be longer than 25 characters"),
        regex(
            path = "USERNAME_REGEX",
            message = "Username can only contain letters, numbers, and underscores"
        )
    )]
    pub username: String,

    // Optional password - if not provided, a temporary one will be generated
    #[validate(
        length(min = 8, max = 25, message = "Password must be between 8 and 25 characters"),
        custom = "validate_password_complexity"
    )]
    pub password: Option<String>,

    // Admin can decide if user is pre-verified
    #[serde(default)]
    pub verified: bool,

    // Admin can set the role
    pub role: UserRole,

    // Admin can send welcome email with credentials
    #[serde(default)]
    pub send_welcome_email: bool,

    // Admin can set if user should be forced to change password on first login
    #[serde(default = "default_force_password_change")]
    pub force_password_change: bool,
}

/// Default to forcing password change for admin-created users
fn default_force_password_change() -> bool {
    true
}

use regex::Regex;
use lazy_static::lazy_static;

/// Custom password validator function
fn validate_password_complexity(password: &str) -> Result<(), ValidationError> {
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_number = password.chars().any(|c| c.is_numeric());
    let has_special = Regex::new(r#"[!@#$%^&*(),.?\":{}<>]"#).unwrap().is_match(password);

    if !has_uppercase || !has_number || !has_special {
        return Err(
            ValidationError::new(
                "Password must contain at least one uppercase letter, one number, and one special character"
            )
        );
    }

    Ok(())
}

lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminCreateUserResponse {
    pub message: String,
    pub user_id: uuid::Uuid,
    pub temporary_password: Option<String>, // Only returned if password was generated
    pub verification_required: bool,
}