use std::sync::Arc;
use axum::{ extract::{ State, Path }, routing::{ get, patch }, Router, Json, http::StatusCode };
use diesel::{
    prelude::*,
    r2d2::{ PooledConnection, ConnectionManager },
    PgConnection,
    result::Error,
};
use crate::{
    models::User,
    schema::users::{ self },
    AppState,
    database::{ operations::users::{ create_user, update_user, delete_user }, DbConnExt },
    routes::api::{ CreateUserRequest, UpdateUserRequest },
    errors::{ HttpError, ErrorMessage },
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
pub async fn get_users(State(state): State<Arc<AppState>>) -> Result<Json<Vec<User>>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    // Execute the query (directly, no interact needed)
    let users_result: Result<Vec<User>, Error> = users::table
        .select(User::as_select())
        .load(&mut *conn);

    match users_result {
        Ok(users) => Ok(Json(users)),
        Err(_) => Err(HttpError::server_error(ErrorMessage::DatabaseError.to_string())),
    }
}

// GET USER BY ID
pub async fn get_user_by_id(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i32>
) -> Result<Json<User>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    // Query the database for the user
    let user_result = users::table
        .find(user_id) // Using find for primary key lookup
        .select(User::as_select())
        .first(&mut *conn)
        .map_err(|e| {
            match e {
                Error::NotFound => {
                    HttpError::new(
                        ErrorMessage::UserNoLongerExists.to_string(),
                        StatusCode::NOT_FOUND
                    )
                }
                _ => HttpError::server_error(ErrorMessage::DatabaseError.to_string()),
            }
        })?;

    Ok(Json(user_result))
}

// CREATE NEW USER
pub async fn create_user_handler(
    State(state): State<Arc<AppState>>,
    Json(user_data): Json<CreateUserRequest>
) -> Result<Json<User>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    create_user(&mut conn, user_data.email, user_data.name, user_data.username, user_data.password)
        .map(Json)
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                HttpError::unique_constraint_validation(ErrorMessage::UserExists.to_string())
            } else {
                HttpError::server_error(ErrorMessage::UserCreationError.to_string())
            }
        })
}

// UPDATE USER BY ID
pub async fn update_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i32>,
    Json(update_data): Json<UpdateUserRequest>
) -> Result<Json<User>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    update_user(
        &mut conn,
        user_id,
        update_data.email,
        update_data.name,
        update_data.username,
        update_data.password
    )
        .map(Json)
        .map_err(|_| { HttpError::server_error(ErrorMessage::UserUpdateError.to_string()) })
}

// DELETE USER BY ID
pub async fn delete_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i32>
) -> Result<StatusCode, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    match delete_user(&mut conn, user_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT), // If successful, return No Content status
        Err(Error::NotFound) => {
            // If user is not found, return Not Found status with a specific message
            Err(HttpError::not_found(ErrorMessage::UserNotFound.to_string()))
        }
        Err(_) => {
            // For any other errors, return Internal Server Error with a message
            Err(HttpError::server_error(ErrorMessage::DeleteUserError.to_string()))
        }
    }
}
