use serde::{ Deserialize, Serialize };
use validator::Validate;

use crate::dto::user_dtos::CreateUserRequest;

pub type SignupRequest = CreateUserRequest;

#[derive(Serialize, Deserialize)]
pub struct SignupResponse {
    pub message: String,
    pub user_id: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    #[validate(length(min = 1, message = "Email is required"), email(message = "Email is invalid"))]
    pub email: String,

    #[validate(
        length(min = 1, message = "Password is required"),
        length(min = 8, message = "Password must be at least 8 characters"),
        length(max = 25, message = "Password too long, password must be no more than 25 characters")
    )]
    pub password: String,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct VerifyEmailQueryDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
}
