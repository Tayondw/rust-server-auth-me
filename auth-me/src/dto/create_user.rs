use serde::{ Deserialize, Serialize };
use uuid::Uuid;
use regex::Regex;
use lazy_static::lazy_static;
use validator::{ Validate, ValidationError };
use chrono::NaiveDateTime;

use crate::models::UserRole;

#[derive(Validate, Debug, Clone, Serialize, Deserialize)]
pub struct SelfSignupRequest {
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

    #[validate(
        length(min = 8, max = 25, message = "Password must be between 8 and 25 characters"),
        custom = "validate_password_complexity"
    )]
    pub password: String,

    #[validate(
        length(min = 1, message = "Confirm Password is required"),
        must_match(other = "password", message = "passwords do not match")
    )]
    #[serde(rename = "passwordConfirm")]
    pub password_confirm: String,

    #[validate(custom = "validate_terms_acceptance")]
    pub terms_accepted: bool,
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

    // Admin can set the role
    pub role: UserRole,

    // Admin can decide if user is pre-verified
    #[serde(default)]
    pub verified: bool,

    // Admin can set if user should be forced to change password on first login
    #[serde(default)]
    pub force_password_change: bool,

    // Admin can send welcome email
    #[serde(default = "default_true")]
    pub send_welcome_email: bool,
}

fn default_true() -> bool {
    true
}

// Custom password validator function
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

fn validate_terms_acceptance(terms: &bool) -> Result<(), ValidationError> {
    if *terms { Ok(()) } else { Err(ValidationError::new("Terms must be accepted")) }
}

// Unified internal creation request
pub struct CreateUserParams {
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub role: UserRole,
    pub verified: bool,
    pub token_expires_at: Option<NaiveDateTime>,
    pub created_by: Option<Uuid>, // Track who created the user
    pub force_password_change: bool,
    pub send_welcome_email: bool,
    pub send_verification_email: bool,
}
