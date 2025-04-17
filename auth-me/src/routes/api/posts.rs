use std::{ sync::Arc, collections::HashMap };
use axum::{
    extract::{ State, Path, Query },
    routing::{ get, post, patch },
    Router,
    Json,
    http::StatusCode,
};
use diesel::prelude::*;
use crate::{
    models::Post,
    schema::posts::{ self, id, title, content },
    AppState,
    database::operations::posts::{ get_posts_by_user, create_post, update_post, delete_post },
};
use serde::{ Deserialize, Serialize };

#[derive(Serialize)]
pub struct ErrorResponse {
    pub message: String,
}

// POST ROUTER
pub fn post_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/posts", get(get_posts).post(create_post_handler))
        .route(
            "/posts/{id}",
            patch(update_post_handler).get(get_post_by_id).delete(delete_post_handler)
        )
        .route("/posts/user/{user_id}", get(get_posts_by_user_handler))
}

// GET ALL POSTS
pub async fn get_posts(State(state): State<Arc<AppState>>) -> Result<
    Json<Vec<Post>>,
    (StatusCode, Json<ErrorResponse>)
> {
    // Get a connection from the pool (no await needed for r2d2)
    let mut conn: diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<PgConnection>> = state.db_pool
        .get()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Database connection error: {}", e),
                }),
            )
        })?;

    // Execute the query (directly, no interact needed)
    let posts_result: Result<Vec<Post>, (StatusCode, Json<ErrorResponse>)> = posts::table
        .select(Post::as_select())
        .load(&mut *conn)
        .map_err(|e: diesel::result::Error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Database error: {}", e),
                }),
            )
        });

    match posts_result {
        Ok(posts) => Ok(Json(posts)),
        Err(e) => Err(e),
    }
}

// GET POST BY ID
pub async fn get_post_by_id(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<i32>
) -> Result<Json<Post>, (StatusCode, Json<ErrorResponse>)> {
    let mut conn = state.db_pool.get().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: format!("Database connection error: {}", e),
            }),
        )
    })?;

    // Query the database for the user
    let post_result = posts::table
        .find(post_id) // Using find for primary key lookup
        .select(Post::as_select())
        .first(&mut *conn)
        .map_err(|e| {
            match e {
                diesel::result::Error::NotFound =>
                    (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            message: format!("Post with id {} not found", post_id),
                        }),
                    ),
                _ =>
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            message: format!("Database error: {}", e),
                        }),
                    ),
            }
        });

    match post_result {
        Ok(post) => Ok(Json(post)),
        Err(e) => Err(e),
    }
}

// GET POSTS BY USER
#[derive(Deserialize)]
pub struct PostQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    sort: Option<String>,
}

pub async fn get_posts_by_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user): Path<i32>,
    Query(query): Query<PostQuery>
) -> Result<Json<Vec<Post>>, (StatusCode, Json<ErrorResponse>)> {
    let mut conn = state.db_pool.get().map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            message: format!("Database connection error: {}", e),
        }),
    ))?;

    let limit = query.limit.unwrap_or(10);
    let offset = query.offset.unwrap_or(0);
    let sort_order = query.sort.clone(); // asc or desc

    match get_posts_by_user(&mut conn, user, limit, offset, sort_order) {
        Ok(posts) => Ok(Json(posts)),
        Err(e) =>
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Error fetching posts for user {}: {}", user, e),
                }),
            )),
    }
}

// CREATE NEW POST
#[derive(serde::Deserialize)]
pub struct CreatePostRequest {
    title: String,
    content: String,
    user_id: i32,
}

pub async fn create_post_handler(
    State(state): State<Arc<AppState>>,
    Json(post_data): Json<CreatePostRequest>
) -> Result<Json<Post>, (StatusCode, Json<ErrorResponse>)> {
    let mut conn = state.db_pool.get().map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            message: format!("Database connection error: {}", e),
        }),
    ))?;

    create_post(&mut conn, post_data.title, post_data.content, post_data.user_id)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: format!("Failed to create post: {}", e),
            }),
        ))
        .map(Json)
}

// UPDATE POST BY ID
#[derive(serde::Deserialize)]
pub struct UpdatePostRequest {
    #[serde(default)] // This makes the field optional in JSON
    title: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

pub async fn update_post_handler(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<i32>,
    Json(update_data): Json<UpdatePostRequest>
) -> Result<Json<Post>, (StatusCode, Json<ErrorResponse>)> {
    let mut conn: diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<PgConnection>> = state.db_pool
        .get()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Database connection error: {}", e),
                }),
            )
        })?;

    update_post(&mut conn, post_id, update_data.title, update_data.content)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Failed to update post: {}", e),
                }),
            )
        })
        .map(Json)
}

// DELETE POST BY ID
pub async fn delete_post_handler(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<i32>
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let mut conn: diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<PgConnection>> = state.db_pool
        .get()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Database connection error: {}", e),
                }),
            )
        })?;

    match delete_post(&mut conn, post_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(diesel::result::Error::NotFound) =>
            Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    message: format!("Post with id {} not found", post_id),
                }),
            )),
        Err(e) =>
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Failed to delete post: {}", e),
                }),
            )),
    }
}
