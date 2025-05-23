pub mod user_dtos;
pub mod authentication_dtos;

use serde::Serialize;

#[derive(Serialize)]
pub struct Response {
    pub message: String,
    pub status: String,
}