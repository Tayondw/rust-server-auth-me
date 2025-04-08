use std::sync::Arc;
use axum::{ extract::{ State, Path }, routing::{ get, post }, Router, Json, http::StatusCode };
use diesel::prelude::*;
use crate::{ models::{ User, NewUser, UpdateUser }, schema::users, schema::users::id, AppState };

#[derive(serde::Serialize)]
struct ErrorResponse {
    message: String,
}

// pub fn user_routes() -> Router<Arc<AppState>> {
//     Router::new()
//         .route("/users", get(get_users).post(create_user))
//         .route("/users/{id}", get(get_user))
// }

pub async fn get_users(State(state): State<Arc<AppState>>) -> Result<
    Json<Vec<User>>,
    (StatusCode, Json<ErrorResponse>)
> {
    // Get a connection from the pool (no await needed for r2d2)
    let mut conn: diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<PgConnection>> = state.db_pool.get().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: format!("Database connection error: {}", e),
            }),
        )
    })?;

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
