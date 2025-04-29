use chrono::{ DateTime, Utc };
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

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
