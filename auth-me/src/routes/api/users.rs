use std::sync::Arc;
use axum::{ extract::{ State, Path }, routing::{ get, patch }, Router, Json, http::StatusCode };
use diesel::prelude::*;
use crate::{
    models::User,
    schema::users::{ self },
    AppState,
    ErrorResponse,
    database::{ operations::users::{ create_user, update_user, delete_user }, DbConnExt },
    routes::api::{ CreateUserRequest, UpdateUserRequest },
};

// USER ROUTER
pub fn user_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/users", get(get_users).post(create_user_handler))
        .route(
            "/users/{id}",
            patch(update_user_handler).get(get_user_by_id).delete(delete_user_handler)
        )
}

// GET ALL USERS
pub async fn get_users(State(state): State<Arc<AppState>>) -> Result<
    Json<Vec<User>>,
    (StatusCode, Json<ErrorResponse>)
> {
    let mut conn = state.conn()?;

    // Execute the query (directly, no interact needed)
    let users_result: Result<Vec<User>, (StatusCode, Json<ErrorResponse>)> = users::table
        .select(User::as_select())
        .load(&mut *conn)
        .map_err(|e: diesel::result::Error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Database error: {}", e),
                }),
            )
        });

    match users_result {
        Ok(users) => Ok(Json(users)),
        Err(e) => Err(e),
    }
}

// GET USER BY ID
pub async fn get_user_by_id(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i32>
) -> Result<Json<User>, (StatusCode, Json<ErrorResponse>)> {
    let mut conn = state.conn()?;

    // Query the database for the user
    let user_result = users::table
        .find(user_id) // Using find for primary key lookup
        .select(User::as_select())
        .first(&mut *conn)
        .map_err(|e| {
            match e {
                diesel::result::Error::NotFound =>
                    (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            message: format!("User with id {} not found", user_id),
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

    match user_result {
        Ok(user) => Ok(Json(user)),
        Err(e) => Err(e),
    }
}

// CREATE NEW USER
pub async fn create_user_handler(
    State(state): State<Arc<AppState>>,
    Json(user_data): Json<CreateUserRequest>
) -> Result<Json<User>, (StatusCode, Json<ErrorResponse>)> {
    let mut conn = state.conn()?;

    create_user(&mut conn, user_data.email, user_data.name, user_data.username, user_data.password)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Failed to create user: {}", e),
                }),
            )
        })
        .map(Json)
}

// UPDATE USER BY ID
pub async fn update_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i32>,
    Json(update_data): Json<UpdateUserRequest>
) -> Result<Json<User>, (StatusCode, Json<ErrorResponse>)> {
    let mut conn = state.conn()?;

    update_user(
        &mut conn,
        user_id,
        update_data.email,
        update_data.name,
        update_data.username,
        update_data.password
    )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Failed to update user: {}", e),
                }),
            )
        })
        .map(Json)
}

// DELETE USER BY ID
pub async fn delete_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i32>
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let mut conn = state.conn()?;

    match delete_user(&mut conn, user_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(diesel::result::Error::NotFound) =>
            Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    message: format!("User with id {} not found", user_id),
                }),
            )),
        Err(e) =>
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Failed to delete user: {}", e),
                }),
            )),
    }
}
