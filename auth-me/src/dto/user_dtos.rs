use chrono::{ NaiveDateTime, DateTime, Utc };
use serde::{ Deserialize, Serialize };
use core::str;
use regex::Regex;
use validator::{ Validate, ValidationError };
use lazy_static::lazy_static;
use uuid::Uuid;

use crate::{ models::{ User, UserRole } };

#[derive(Validate, Debug, Clone, Serialize, Deserialize)]
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

    #[serde(default)]
    pub verified: bool,

    pub token_expires_at: Option<DateTime<Utc>>,

    #[validate(custom = "validate_terms_acceptance")]
    pub terms_accepted: bool,

    // SECURITY: Role field is optional and will be ignored for self-signup
    // This allows the client to send it but we'll validate and ignore it
    pub role: Option<UserRole>,

    pub created_by: Option<Uuid>,

    // Set to false since it is created by user
    #[serde(default = "default_force_password_change")]
    pub force_password_change: bool,
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

// Regex for username validation (letters, numbers, underscores only
lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();
}

// Custom validator for terms acceptance
fn validate_terms_acceptance(terms: &bool) -> Result<(), ValidationError> {
    if !terms {
        return Err(validator::ValidationError::new("terms_not_accepted"));
    }
    Ok(())
}

/// Default to forcing password change for self-created users
fn default_force_password_change() -> bool {
    false
}

#[derive(Debug)]
pub enum UserQuery {
    Id(Uuid),
    Email(String),
    Name(String),
    Username(String),
    Token(String),
    Role(UserRole),
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
    pub role: String,
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
            role: user.role.to_str().to_string(),
            created_at: user.created_at.unwrap(),
            updated_at: user.updated_at.unwrap(),
        }
    }

    pub fn filter_users(user: &[User]) -> Vec<FilterUser> {
        user.iter().map(FilterUser::filter_user).collect()
    }
}

#[derive(Serialize, Deserialize, Validate)]
pub struct UserSearchQuery {
    #[validate(range(min = 1, max = 100))]
    pub page: Option<usize>,

    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,

    #[validate(length(min = 1, max = 100))]
    pub search: Option<String>,

    pub role: Option<UserRole>,

    pub verified: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub user: FilterUser,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserListResponse {
    pub status: String,
    pub users: Vec<FilterUser>,
    pub results: usize,
    pub page: usize,
    pub limit: usize,
    pub total_pages: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SingleUserResponse {
    pub status: String,
    pub data: UserData,
}

#[derive(Deserialize, Validate, Debug)]
pub struct UpdateUserRequest {
    #[serde(default)]
    #[validate(
        length(min = 1, message = "Name is required"),
        length(max = 25, message = "Name cannot be longer than 25 characters")
    )]
    pub name: Option<String>,

    #[serde(default)]
    #[validate(length(min = 1, message = "Email is required"), email(message = "Email is invalid"))]
    pub email: Option<String>,

    #[serde(default)]
    #[validate(
        length(min = 1, message = "Username is required"),
        length(max = 25, message = "Username cannot be longer than 25 characters"),
        regex(
            path = "USERNAME_REGEX",
            message = "Username can only contain letters, numbers, and underscores"
        )
    )]
    pub username: Option<String>,

    #[serde(default)]
    #[validate(
        length(min = 8, max = 25, message = "Password must be between 8 and 25 characters"),
        custom = "validate_password_complexity"
    )]
    pub password: Option<String>,

    #[serde(default)]
    pub verified: Option<bool>,

    #[serde(default)]
    pub role: Option<UserRole>,

    #[serde(default, rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 1, message = "Please enter your password"))]
    pub current_password: String,

    #[validate(
      length(min = 8, max = 25, message = "Password must be between 8 and 25 characters"),
      custom = "validate_password_complexity"
  )]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SelfDeleteRequest {
    #[validate(length(min = 1, message = "Please enter your password"))]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteUserResponse {
    pub message: String,
    pub status: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserStatistics {
    pub total_users: usize,
    pub verified_users: usize,
    pub unverified_users: usize,
    pub admin_users: usize,
    pub moderator_users: usize,
    pub regular_users: usize,
}

#[derive(Debug, Deserialize)]
pub struct AdvancedUserFilters {
    pub search_term: Option<String>,
    pub roles: Option<Vec<UserRole>>,
    pub verified: Option<bool>,
    pub created_after: Option<NaiveDateTime>,
    pub created_before: Option<NaiveDateTime>,
    pub sort_by: Option<UserSortBy>,
    pub sort_desc: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub enum UserSortBy {
    CreatedAt,
    Name,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RoleUpdateDto {
    #[validate(custom = "validate_user_role")]
    pub role: UserRole,
}

fn validate_user_role(role: &UserRole) -> Result<(), validator::ValidationError> {
    match role {
        UserRole::Admin | UserRole::User => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_role")),
    }
}

// Request/Response structs
#[derive(Debug, Serialize, Deserialize)]
pub struct UserStatisticsResponse {
    pub status: String,
    pub data: UserStatistics,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdvancedSearchQuery {
    #[validate(range(min = 1, max = 100))]
    pub page: Option<usize>,

    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,

    #[validate(length(min = 1, max = 100))]
    pub search_term: Option<String>,

    pub roles: Option<Vec<UserRole>>,
    pub verified: Option<bool>,
    pub created_after: Option<chrono::NaiveDateTime>,
    pub created_before: Option<chrono::NaiveDateTime>,
    pub sort_by: Option<UserSortBy>,
    pub sort_desc: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct BulkRoleUpdateRequest {
    #[validate(length(min = 1, max = 1000))]
    pub user_ids: Vec<Uuid>,
    pub new_role: UserRole,
}

#[derive(Debug, Serialize)]
pub struct BulkOperationResponse {
    pub status: String,
    pub affected_count: usize,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CleanupResponse {
    pub status: String,
    pub cleaned_count: usize,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CacheStatisticsResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct CacheInvalidationRequest {
    pub pattern: String,
}

#[derive(Debug, Serialize)]
pub struct CacheInvalidationResponse {
    pub status: String,
    pub invalidated_count: usize,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
