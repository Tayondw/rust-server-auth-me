pub mod user_dtos;
pub mod authentication_dtos;
pub mod create_user_dtos;
pub mod email_dtos;

use serde::Serialize;

#[derive(Serialize)]
pub struct Response {
    pub message: String,
    pub status: String,
}