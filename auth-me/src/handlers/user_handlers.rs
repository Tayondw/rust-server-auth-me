use std::sync::Arc;

use axum::{ extract::{ State, Path }, Json, http::StatusCode };
use diesel::{
    prelude::*,
    r2d2::{ PooledConnection, ConnectionManager },
    PgConnection,
    result::Error,
};
use uuid::Uuid;
use serde_json::{json, Value};

use crate::{
    models::User,
    schema::users::{ self },
    AppState,
    database::DbConnExt,
    operations::user_operations::{ create_user, update_user, delete_user },
    errors::{ HttpError, ErrorMessage },
    dto::user_dtos::{ CreateUserRequest, UpdateUserRequest },
};

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
    Path(user_id): Path<Uuid>
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

    create_user(
        &mut conn,
        user_data.email,
        user_data.name,
        user_data.username,
        user_data.password,
        user_data.verified
    )
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
    Path(user_id): Path<Uuid>,
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
    Path(user_id): Path<Uuid>
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

pub async fn list_users(State(state): State<Arc<AppState>>) -> Result<Json<Value>, HttpError> {
    // Basic user list for managers - limited info
    let users =
        json!({
        "users": [
            {
                "id": 1,
                "email": "user1@example.com",
                "role": "User",
                "active": true
            },
            {
                "id": 2,
                "email": "user2@example.com", 
                "role": "User",
                "active": true
            }
        ],
        "total_count": 2
    });

    Ok(Json(users))
}

pub async fn list_all_users(State(state): State<Arc<AppState>>) -> Result<Json<Value>, HttpError> {
    // Full user list for admins - includes sensitive info
    let users =
        json!({
        "users": [
            {
                "id": 1,
                "email": "user1@example.com",
                "role": "User",
                "active": true,
                "created_at": "2024-01-10T08:00:00Z",
                "last_login": "2024-01-20T14:30:00Z",
                "email_verified": true
            },
            {
                "id": 2,
                "email": "user2@example.com",
                "role": "User", 
                "active": true,
                "created_at": "2024-01-12T09:15:00Z",
                "last_login": "2024-01-19T16:45:00Z",
                "email_verified": true
            },
            {
                "id": 3,
                "email": "admin@example.com",
                "role": "Admin",
                "active": true,
                "created_at": "2024-01-01T00:00:00Z",
                "last_login": "2024-01-21T10:00:00Z",
                "email_verified": true
            }
        ],
        "total_count": 3,
        "admin_count": 1,
        "active_count": 3
    });

    Ok(Json(users))
}
