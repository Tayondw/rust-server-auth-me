use std::sync::Arc;

use axum::{ extract::{ State, Path, Query }, Json, http::StatusCode };
use diesel::{ r2d2::{ PooledConnection, ConnectionManager }, PgConnection };
use uuid::Uuid;
use serde_json::{ json, Value };
use validator::Validate;

use crate::{
    config::ConfigError,
    database::DbConnExt,
    dto::user_dtos::{
        CreateUserRequest,
        FilterUser,
        RequestQuery,
        SingleUserResponse,
        UpdateUserRequest,
        UserData,
        UserListResponse,
        UserQuery,
        UserSearchQuery,
    },
    errors::{ ErrorMessage, HttpError },
    models::User,
    operations::user_operations::*,
    repositories::user_repository::UserRepository,
    services::{ cache_services::CacheService, enhanced_cache_services::EnhancedCacheService },
    AppState,
};

const USER_CACHE_TTL: u64 = 300; // 5 minutes
const USER_LIST_CACHE_TTL: u64 = 60; // 1 minute
const SEARCH_CACHE_TTL: u64 = 30; // 30 seconds

/// GET ALL USERS
pub async fn get_users(
    Query(query_params): Query<RequestQuery>,
    State(state): State<Arc<AppState>>
) -> Result<Json<UserListResponse>, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(format!("Validation error: {}", e)))?;

    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);
    let cache_key = format!("users_paginated:{}:{}", page, limit);

    // Try cache first
    if
        let Some(cached_response) = enhanced_cache.cache_service.get::<UserListResponse>(
            &cache_key
        ).await
    {
        return Ok(Json(cached_response));
    }

    // Get from database
    let (users, total_count) = UserRepository::get_users_paginated(
        &state.config.database.pool,
        page,
        limit
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    let total_pages = (((total_count as usize) + limit - 1) / limit).max(1);

    let response = UserListResponse {
        status: "success".to_string(),
        users: FilterUser::filter_users(&users),
        results: total_count as usize,
        page,
        limit,
        total_pages,
    };

    // Cache with tags
    let tags = vec!["users_list".to_string()];
    enhanced_cache.set_with_tags(&cache_key, &response, USER_LIST_CACHE_TTL, tags).await;

    Ok(Json(response))
}

/// GET USER BY ID
pub async fn get_user_by_id(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>
) -> Result<Json<SingleUserResponse>, HttpError> {
    let cache_key = format!("user:{}", user_id);

    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    // Try cache first
    if
        let Some(cached_response) = enhanced_cache.cache_service.get::<SingleUserResponse>(
            &cache_key
        ).await
    {
        return Ok(Json(cached_response));
    }

    // Get from database
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

    let response = SingleUserResponse {
        status: "success".to_string(),
        data: UserData {
            user: FilterUser::filter_user(&user),
        },
    };

    // Cache with tags including user-specific and role-specific tags
    let tags = vec![
        format!("user:{}", user_id),
        format!("role:{:?}", user.role),
        format!("verified:{}", user.verified)
    ];
    enhanced_cache.set_with_tags(&cache_key, &response, USER_CACHE_TTL, tags).await;

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

    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

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

    // Try cache first
    if
        let Some(cached_response) = enhanced_cache.cache_service.get::<UserListResponse>(
            &cache_key
        ).await
    {
        return Ok(Json(cached_response));
    }

    // Get from database
    let (users, total_count) = UserRepository::search_users(
        &state.config.database.pool,
        page,
        limit,
        query_params.search.as_deref(),
        query_params.role,
        query_params.verified
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    let total_pages = (((total_count as usize) + limit - 1) / limit).max(1);

    let response = UserListResponse {
        status: "success".to_string(),
        users: FilterUser::filter_users(&users),
        results: total_count as usize,
        page,
        limit,
        total_pages,
    };

    // Cache with comprehensive tags
    let mut tags = vec!["users_search".to_string()];
    if let Some(role) = query_params.role {
        tags.push(format!("role:{:?}", role));
    }
    if let Some(verified) = query_params.verified {
        tags.push(format!("verified:{}", verified));
    }

    enhanced_cache.set_with_tags(&cache_key, &response, SEARCH_CACHE_TTL, tags).await;

    Ok(Json(response))
}

// CREATE NEW USER
pub async fn create_user_handler(
    State(state): State<Arc<AppState>>,
    Json(user_data): Json<CreateUserRequest>
) -> Result<Json<User>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    create_user(
        &mut conn,
        user_data.name,
        user_data.email,
        user_data.username,
        user_data.password,
        user_data.verified,
        user_data.token_expires_at,
        user_data.role
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

/// UPDATE USER BY ID
pub async fn update_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    Json(update_data): Json<UpdateUserRequest>
) -> Result<Json<User>, HttpError> {
    let mut conn: PooledConnection<ConnectionManager<PgConnection>> = state.conn()?;

    UserRepository::update_user(&mut conn, user_id, update_data)
        .map(Json)
        .map_err(|_| HttpError::server_error(ErrorMessage::UserUpdateError.to_string()))
}

/// UPDATE USER WITH CACHE INVALIDATION
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    Json(update_data): Json<UpdateUserRequest>
) -> Result<Json<SingleUserResponse>, HttpError> {
    // Get a connection from the pool
    let mut conn = state.conn()?;

    // Get the current user for cache invalidation comparison
    let old_user = UserRepository::get_user(&state.config.database.pool, UserQuery::Id(user_id))
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(||
            HttpError::new(ErrorMessage::UserNoLongerExists.to_string(), StatusCode::NOT_FOUND)
        )?;

    // Perform the update
    let updated_user = UserRepository::update_user(&mut conn, user_id, update_data).map_err(|e|
        HttpError::server_error(e.to_string())
    )?;

    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    // Invalidate cache based on what changed
    if
        let Err(e) = enhanced_cache.invalidate_for_user_update(
            user_id,
            Some(&old_user),
            Some(&updated_user)
        ).await
    {
        // Log the error but don't fail the request
        tracing::warn!("Failed to invalidate cache after user update: {}", e);
    }

    let response = SingleUserResponse {
        status: "success".to_string(),
        data: UserData {
            user: FilterUser::filter_user(&updated_user),
        },
    };

    Ok(Json(response))
}

/// DELETE USER WITH CACHE INVALIDATION
pub async fn delete_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>
) -> Result<StatusCode, HttpError> {
    // Get the user before deletion for cache invalidation
    let user_to_delete = UserRepository::get_user(
        &state.config.database.pool,
        UserQuery::Id(user_id)
    )
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(||
            HttpError::new(ErrorMessage::UserNoLongerExists.to_string(), StatusCode::NOT_FOUND)
        )?;

    // Perform the deletion
    UserRepository::delete_user(&state.config.database.pool, user_id).map_err(|e|
        HttpError::server_error(e.to_string())
    )?;

    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    // Invalidate all related cache entries
    if
        let Err(e) = enhanced_cache.invalidate_for_user_update(
            user_id,
            Some(&user_to_delete),
            None
        ).await
    {
        tracing::warn!("Failed to invalidate cache after user deletion: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_users(State(_state): State<Arc<AppState>>) -> Result<Json<Value>, HttpError> {
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

pub async fn list_all_users(State(_state): State<Arc<AppState>>) -> Result<Json<Value>, HttpError> {
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
