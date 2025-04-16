use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct TestRequest {
    pub hello: String,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}
