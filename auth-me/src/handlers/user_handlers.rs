use std::sync::Arc;

use axum::{ extract::{ State, Path, Query }, Json, http::StatusCode };
use diesel::{ r2d2::{ PooledConnection, ConnectionManager }, PgConnection, result::Error };
use uuid::Uuid;
use serde_json::{ json, Value };
use validator::Validate;

use crate::{
    models::User,
    config::ConfigError,
    AppState,
    database::DbConnExt,
    operations::user_operations::{ create_user, update_user, delete_user },
    errors::{ HttpError, ErrorMessage },
    dto::user_dtos::{
        CreateUserRequest,
        UpdateUserRequest,
        RequestQuery,
        UserListResponse,
        FilterUser,
        UserSearchQuery,
        UserData,
        SingleUserResponse,
        UserQuery,
    },
    repositories::user_repository::UserRepository,
    services::cache_services::CacheService,
};

const USER_CACHE_TTL: u64 = 300; // 5 minutes
const USER_LIST_CACHE_TTL: u64 = 60; // 1 minute
const SEARCH_CACHE_TTL: u64 = 30; // 30 seconds

/// GET ALL USERS
pub async fn get_users(
    Query(query_params): Query<RequestQuery>,
    State(state): State<Arc<AppState>>
) -> Result<Json<UserListResponse>, HttpError> {
    // Validate input
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(format!("Validation error: {}", e)))?;

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    // Generate cache key for pagination
    let cache_service = CacheService::new(state.config.cache.clone());
    let cache_key = format!("users_paginated:{}:{}", page, limit);

    // Try to get from cache first
    if let Some(cached_response) = cache_service.get::<UserListResponse>(&cache_key).await {
        return Ok(Json(cached_response));
    }

    // If not in cache, get from database using repository
    let (users, total_count) = UserRepository::get_users_paginated(
        &state.config.database.pool,
        page,
        limit
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    let total_pages = (((total_count as usize) + limit - 1) / limit).max(1);

    // Return filtered response (no raw models exposed)
    let response = UserListResponse {
        status: "success".to_string(),
        users: FilterUser::filter_users(&users), // This filters out sensitive data
        results: total_count as usize,
        page,
        limit,
        total_pages,
    };

    // Cache the response
    cache_service.set(&cache_key, &response, USER_LIST_CACHE_TTL).await;

    Ok(Json(response))
}

/// GET USER BY ID
pub async fn get_user_by_id(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>
) -> Result<Json<SingleUserResponse>, HttpError> {
    let cache_service = CacheService::new(state.config.cache.clone());
    let cache_key = format!("user:{}", user_id);

    // Try to get from cache first
    if let Some(cached_response) = cache_service.get::<SingleUserResponse>(&cache_key).await {
        return Ok(Json(cached_response));
    }

    // If not in cache, get from database using repository
    let user = UserRepository::get_user(&state.config.database.pool, UserQuery::Id(user_id))
        .map_err(|e| {
            match e {
                ConfigError::NotFound =>
                    HttpError::new(
                        ErrorMessage::UserNoLongerExists.to_string(),
                        StatusCode::NOT_FOUND
                    ),
                _ => HttpError::server_error(e.to_string()),
            }
        })?
        .ok_or_else(|| {
            HttpError::new(ErrorMessage::UserNoLongerExists.to_string(), StatusCode::NOT_FOUND)
        })?;

    // Create response
    let response = SingleUserResponse {
        status: "success".to_string(),
        data: UserData {
            user: FilterUser::filter_user(&user),
        },
    };

    // Cache the response
    cache_service.set(&cache_key, &response, USER_CACHE_TTL).await;

    Ok(Json(response))
}

// SEARCH USERS - Advanced filtering w/ caching
pub async fn search_users(
    Query(query_params): Query<UserSearchQuery>,
    State(state): State<Arc<AppState>>
) -> Result<Json<UserListResponse>, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(format!("Validation error: {}", e)))?;

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    // Generate cache key for search
    let cache_service = CacheService::new(state.config.cache.clone());
    let cache_key = format!(
        "users_search:{}:{}:{}:{}:{}",
        page,
        limit,
        query_params.search.as_deref().unwrap_or(""),
        query_params.role
            .as_ref()
            .map(|r| format!("{:?}", r))
            .unwrap_or_default(),
        query_params.verified.map(|v| v.to_string()).unwrap_or_default()
    );

    // Try to get from cache first
    if let Some(cached_response) = cache_service.get::<UserListResponse>(&cache_key).await {
        return Ok(Json(cached_response));
    }

    // If not in cache, search in database using repository
    let (users, total_count) = UserRepository::search_users(
        &state.config.database.pool,
        page,
        limit,
        query_params.search.as_deref(),
        query_params.role,
        query_params.verified
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    let total_pages = (((total_count as usize) + limit - 1) / limit).max(1);

    // Create response
    let response = UserListResponse {
        status: "success".to_string(),
        users: FilterUser::filter_users(&users),
        results: total_count as usize,
        page,
        limit,
        total_pages,
    };

    // Cache the response (shorter TTL for search results)
    cache_service.set(&cache_key, &response, 30).await; // 30 seconds

    Ok(Json(response))
}

/// Helper function to invalidate user-related cache entries
pub async fn invalidate_user_cache(cache_service: &CacheService, user_id: Option<Uuid>) {
    // Invalidate specific user cache if user_id is provided
    if let Some(id) = user_id {
        let user_cache_key = format!("user:{}", id);
        cache_service.delete(&user_cache_key).await;
    }

    // Note: For paginated results and search results, I will implement
    // a more sophisticated cache invalidation strategy, such as:
    // 1. Using cache keys with wildcards (if Redis supports it)
    // 2. Maintaining a set of active cache keys
    // 3. Using cache tags/groups
    // 
    // For now, you could clear all user list caches or implement a time-based expiration
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
