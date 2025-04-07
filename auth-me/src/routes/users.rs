use std::sync::Arc;
use axum::{ extract::{ State, Path }, routing::{ get, post }, Router, Json, http::StatusCode };
use diesel::prelude::*;
use crate::{ models::{ User, NewUser, UpdateUser }, schema::users, schema::users::id, AppState };

#[derive(serde::Serialize)]
struct ErrorResponse {
    message: String,
}

pub fn user_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/users", get(get_users).post(create_user))
        .route("/users/{id}", get(get_user))
}

pub async fn get_users(State(state): State<Arc<AppState>>) -> Result<
    Json<Vec<User>>,
    (StatusCode, Json<ErrorResponse>)
> {
    // Get a connection from the pool (no await needed for r2d2)
    let mut conn = state.db_pool.get().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: format!("Database connection error: {}", e),
            }),
        )
    })?;

    // Execute the query (directly, no interact needed)
    let users_result = users::table
        .select(User::as_select())
        .load(&mut *conn)
        .map_err(|e| {
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

async fn create_user(
    State(state): State<Arc<AppState>>,
    Json(new_user): Json<NewUser>
) -> Result<Json<User>, (StatusCode, Json<ErrorResponse>)> {
    let mut conn = state.db_pool.get().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: format!("Database connection error: {}", e),
            }),
        )
    })?;

    let created_user = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result::<User>(&mut conn)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Database error: {}", e),
                }),
            )
        })?;

    Ok(Json(created_user))

}

async fn get_user(State(state): State<Arc<AppState>>) -> Json<User> {
    // Handler implementation
}
