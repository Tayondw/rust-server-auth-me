use chrono::{ DateTime, Utc };
use serde::{ Deserialize, Serialize };
use core::str;
use regex::Regex;
use validator::{ Validate, ValidationError };
use lazy_static::lazy_static;
use uuid::Uuid;

use crate::models::User;

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
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

    pub verified: bool,

    #[validate(custom = "validate_terms_acceptance")]
    pub terms_accepted: bool,
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

#[derive(Debug)]
pub enum UserQuery<'a> {
    Id(Uuid),
    Email(&'a str),
    Name(&'a str),
    Username(&'a str),
    Token(&'a str),
}

#[derive(Serialize, Deserialize, Validate)]
pub struct RequestQuery {
    #[validate(range(min = 1))]
    pub page: Option<usize>,

    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub username: String,
    pub verified: bool,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl FilterUser {
    pub fn filter_user(user: &User) -> Self {
        FilterUser {
            id: user.id.to_string(),
            name: user.name.to_owned(),
            email: user.email.to_owned(),
            username: user.username.to_owned(),
            verified: user.verified,
            created_at: user.created_at.unwrap(),
            updated_at: user.updated_at.unwrap(),
        }
    }

    pub fn filter_users(user: &[User]) -> Vec<FilterUser> {
        user.iter().map(FilterUser::filter_user).collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub user: FilterUser,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)] // This makes the field optional in JSON
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}
