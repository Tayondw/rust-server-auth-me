use serde::Deserialize;

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
    pub username: String,
    pub email: String,
    pub password: String,
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

#[derive(Deserialize)]
pub struct PostQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub sort: Option<String>,
}

#[derive(Deserialize)]
pub struct CreatePostRequest {
    pub title: String,
    pub content: String,
    pub user_id: i32,
}

#[derive(Deserialize)]
pub struct UpdatePostRequest {
    #[serde(default)] // This makes the field optional in JSON
    pub title: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}