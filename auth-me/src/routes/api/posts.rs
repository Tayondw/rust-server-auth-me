use std::sync::Arc;
use axum::{
    extract::{ State, Path, Query },
    routing::{ get, patch },
    Router,
    Json,
    http::StatusCode,
};
use diesel::{
    prelude::*,
    result::Error,
    r2d2::{ ConnectionManager, PooledConnection },
    PgConnection,
};

use crate::{
    models::Post,
    schema::posts::{ self },
    AppState,
    database::{
        operations::posts::{ get_posts_by_user, create_post, update_post, delete_post },
        DbConnExt,
    },
    routes::api::{ CreatePostRequest, UpdatePostRequest, PostQuery },
    errors::{ HttpError, ErrorMessage },
};

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
pub async fn get_posts(State(state): State<Arc<AppState>>) -> Result<Json<Vec<Post>>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    // Execute the query (directly, no interact needed)
    let posts_result: Result<Vec<Post>, Error> = posts::table
        .select(Post::as_select())
        .load(&mut *conn);

    match posts_result {
        Ok(posts) => Ok(Json(posts)),
        Err(_) => Err(HttpError::server_error(ErrorMessage::DatabaseError.to_string())),
    }
}

// GET POST BY ID
pub async fn get_post_by_id(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<i32>
) -> Result<Json<Post>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    // Query the database for the post
    let post_result = posts::table
        .find(post_id) // Using find for primary key lookup
        .select(Post::as_select())
        .first(&mut *conn)
        .map_err(|e| {
            match e {
                Error::NotFound =>
                    HttpError::new(ErrorMessage::PostNotFound.to_string(), StatusCode::NOT_FOUND),
                _ => HttpError::server_error(ErrorMessage::DatabaseError.to_string()),
            }
        })?;

    Ok(Json(post_result))
}

// GET POSTS BY USER
pub async fn get_posts_by_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user): Path<i32>,
    Query(query): Query<PostQuery>
) -> Result<Json<Vec<Post>>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    let limit = query.limit.unwrap_or(10);
    let offset = query.offset.unwrap_or(0);
    let sort_order = query.sort.clone(); // asc or desc

    get_posts_by_user(&mut conn, user, limit, offset, sort_order)
        .map(Json)
        .map_err(|_| { HttpError::server_error(ErrorMessage::PostsByUserError.to_string()) })
}

// CREATE NEW POST
pub async fn create_post_handler(
    State(state): State<Arc<AppState>>,
    Json(post_data): Json<CreatePostRequest>
) -> Result<Json<Post>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    create_post(&mut conn, post_data.title, post_data.content, post_data.user_id)
        .map(Json)
        .map_err(|_| HttpError::server_error(ErrorMessage::PostCreationError.to_string()))
}

// UPDATE POST BY ID
pub async fn update_post_handler(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<i32>,
    Json(update_data): Json<UpdatePostRequest>
) -> Result<Json<Post>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    update_post(&mut conn, post_id, update_data.title, update_data.content)
        .map(Json)
        .map_err(|_| HttpError::server_error(ErrorMessage::PostUpdateError.to_string()))
}

// DELETE POST BY ID
pub async fn delete_post_handler(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<i32>
) -> Result<StatusCode, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    match delete_post(&mut conn, post_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(Error::NotFound) => Err(HttpError::not_found(ErrorMessage::PostNotFound.to_string())),
        Err(_) => Err(HttpError::server_error(ErrorMessage::DeletePostError.to_string())),
    }
}
