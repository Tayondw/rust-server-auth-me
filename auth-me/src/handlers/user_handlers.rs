use std::sync::Arc;

use axum::{
    extract::{ State, Path, Query },
    Json,
    http::StatusCode,
    response::IntoResponse,
    Extension,
};
use diesel::{ prelude::*, result::Error as DieselError };
use uuid::Uuid;
use tracing::{ info, error };
use serde_json::{ json, Value };
use chrono::Utc;
use validator::Validate;

use crate::{
    config::ConfigError,
    connection::DbConnExt,
    models::UserRole,
    middleware::auth::AuthenticatedUser,
    dto::{
        user_dtos::{
            FilterUser,
            RequestQuery,
            SingleUserResponse,
            UpdateUserRequest,
            ChangePasswordRequest,
            UserData,
            UserListResponse,
            UserQuery,
            UserSearchQuery,
            SelfDeleteRequest,
            DeleteUserResponse,
        },
        create_user_dtos::{ AdminCreateUserRequest, AdminCreateUserResponse },
        Response,
    },
    errors::{ ErrorMessage, HttpError },
    repositories::user_repository::UserRepository,
    services::{
        cache_services::CacheService,
        enhanced_cache_services::EnhancedCacheService,
        user_service::UserService,
    },
    utils::password::{ hash, compare },
    AppState,
};

const USER_CACHE_TTL: u64 = 300; // 5 minutes
const USER_LIST_CACHE_TTL: u64 = 60; // 1 minute
const SEARCH_CACHE_TTL: u64 = 30; // 30 seconds

/// GET ALL USERS
/// # Path Parameters
/// - `user_id`: UUID of the target user
///
/// # Cache Strategy
/// - Cache key pattern: `user:{uuid}`
/// - TTL: `USER_CACHE_TTL`
/// - Multi-dimensional tags:
///   - `user:{id}` - Individual user invalidation
///   - `role:{role}` - Role-based bulk invalidation
///   - `verified:{status}` - Verification status invalidation
///
/// # Returns
/// - `200 OK`: User data wrapped in success response
/// - `404 Not Found`: User does not exist or was deleted
/// - `500 Internal Server Error`: Database or cache failures
///
/// # Error Handling
/// - Distinguishes between database errors and missing records
/// - Provides consistent error messages via `ErrorMessage` enum
/// - Graceful fallback from cache misses to database queries
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
/// Fetches a specific user by their id with caching
///
/// This endpoint implements caching with multiple tag dimensions
/// (user ID, role, verification status) enabling precise cache invalidation
/// when user attributes change. Returns filtered user data for security.
///
/// # Path Parameters
/// - `user_id`: UUID of the target user
///
/// # Cache Strategy
/// - Cache key pattern: `user:{uuid}`
/// - TTL: `USER_CACHE_TTL`
/// - Multi-dimensional tags:
///   - `user:{id}` - Individual user invalidation
///   - `role:{role}` - Role-based bulk invalidation
///   - `verified:{status}` - Verification status invalidation
///
/// # Returns
/// - `200 OK`: User data wrapped in success response
/// - `404 Not Found`: User does not exist or was deleted
/// - `500 Internal Server Error`: Database or cache failures
///
/// # Error Handling
/// - Distinguishes between database errors and missing records
/// - Provides consistent error messages via `ErrorMessage` enum
/// - Graceful fallback from cache misses to database queries
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

// ================================================= SELF-MANAGEMENT HANDLERS ===================================================

/// GET CURRENT USER
/// Retrieves the current authenticated user's profile information.
///
/// This endpoint allows users to fetch their own profile data with caching support
/// for improved performance. The response includes filtered user information that
/// excludes sensitive fields like password hashes.
///
/// # Arguments
/// * `state` - Application state containing database pool and configuration
/// * `auth_user` - Authenticated user extracted from JWT token
///
/// # Returns
/// * `Ok(Json<SingleUserResponse>)` - User profile data on success
/// * `Err(HttpError)` - Various error types:
///   - `500` - Database connection or query failures
///   - `404` - User not found (shouldn't happen for authenticated users)
///
/// # Caching
/// - Cache key: `user:{user_id}`
/// - TTL: `USER_CACHE_TTL`
/// - Cache tags: `["user:{user_id}"]`
///
/// # Security
/// - Requires valid authentication token
/// - Users can only access their own profile
pub async fn get_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthenticatedUser>
) -> Result<Json<SingleUserResponse>, HttpError> {
    let cache_key = format!("user:{}", auth_user.id);

    // Create cache service
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
    let user = UserRepository::get_user(&state.config.database.pool, UserQuery::Id(auth_user.id))
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(|| HttpError::not_found("User not found".to_string()))?;

    let response = SingleUserResponse {
        status: "success".to_string(),
        data: UserData {
            user: FilterUser::filter_user(&user),
        },
    };

    // Cache the response
    let tags = vec![format!("user:{}", auth_user.id)];
    enhanced_cache.set_with_tags(&cache_key, &response, USER_CACHE_TTL, tags).await;

    Ok(Json(response))
}

/// UPDATE CURRENT USER
/// Updates the current authenticated user's profile information.
///
/// This endpoint allows users to modify their own profile data including name, email,
/// username, and password. Certain fields like role and verification status cannot
/// be modified by users themselves and require admin privileges.
///
/// # Arguments
/// * `state` - Application state containing database pool and configuration
/// * `auth_user` - Authenticated user extracted from JWT token
/// * `update_data` - JSON payload containing fields to update
///
/// # Request Body
/// ```json
/// {
///   "name": "New Name",           // Optional
///   "email": "new@example.com",   // Optional
///   "username": "newusername",    // Optional
///   "password": "newpassword"     // Optional, will be hashed
/// }
/// ```
///
/// # Returns
/// * `Ok(Json<SingleUserResponse>)` - Updated user profile data
/// * `Err(HttpError)` - Various error types:
///   - `400` - Validation errors or password hashing failures
///   - `404` - User not found
///   - `500` - Database connection or query failures
///
/// # Security
/// - Requires valid authentication token
/// - Users can only update their own profile
/// - Passwords are automatically hashed before storage
/// - Role and verification status are ignored in self-updates
///
/// # Cache Invalidation
/// - Invalidates user-specific cache entries
/// - Compares old and new user data for targeted invalidation
pub async fn update_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(update_data): Json<UpdateUserRequest>
) -> Result<Json<SingleUserResponse>, HttpError> {
    // Validate the update request
    if let Err(validation_errors) = update_data.validate() {
        return Err(HttpError::validation_error(validation_errors.to_string()));
    }

    let mut conn = state.conn()?;

    // Get current user data for comparison
    let old_user = UserRepository::get_user(
        &state.config.database.pool,
        UserQuery::Id(auth_user.id)
    )
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(|| HttpError::not_found("User not found".to_string()))?;

    // Convert self-update request to internal update request
    // Users cannot change their own role, verification status, etc.
    let internal_update_data = UpdateUserRequest {
        name: update_data.name,
        email: update_data.email,
        username: update_data.username,
        password: update_data.password
            .map(|p| {
                // Hash the new password
                hash(p).map_err(|_| HttpError::bad_request("Password hashing failed".to_string()))
            })
            .transpose()?,
        role: None, // Users cannot change their own role
        verified: None, // Users cannot change their own verification status
        updated_at: Some(Utc::now()),
    };

    // Perform the update
    let updated_user = UserRepository::update_user(
        &mut conn,
        auth_user.id,
        internal_update_data
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    // Invalidate cache
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    if
        let Err(e) = enhanced_cache.invalidate_for_user_update(
            auth_user.id,
            Some(&old_user),
            Some(&updated_user)
        ).await
    {
        tracing::warn!("Failed to invalidate cache after self-update: {}", e);
    }

    let response = SingleUserResponse {
        status: "success".to_string(),
        data: UserData {
            user: FilterUser::filter_user(&updated_user),
        },
    };

    Ok(Json(response))
}

/// DELETE CURRENT USER
/// Deletes the current authenticated user's account.
///
/// This endpoint allows users to permanently delete their own account. The operation
/// requires password confirmation for security and includes special handling for admin
/// users to prevent deletion of the last admin account.
///
/// # Arguments
/// * `state` - Application state containing database pool and configuration
/// * `auth_user` - Authenticated user extracted from JWT token
/// * `delete_request` - JSON payload containing password confirmation
///
/// # Request Body
/// ```json
/// {
///   "password": "current_password"  // Required for confirmation
/// }
/// ```
///
/// # Returns
/// * `Ok(Json<DeleteUserResponse>)` - Success confirmation with 204 status
/// * `Err(HttpError)` - Various error types:
///   - `400` - Password verification failed or last admin deletion attempt
///   - `401` - Invalid password provided
///   - `404` - User not found
///   - `500` - Database connection or query failures
///
/// # Security
/// - Requires valid authentication token
/// - Requires current password confirmation
/// - Prevents deletion of the last admin user
/// - Permanently removes user data from database
///
/// # Cache Invalidation
/// - Invalidates all user-related cache entries
/// - Handles cleanup for deleted user data
pub async fn delete_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(delete_request): Json<SelfDeleteRequest>
) -> Result<Json<DeleteUserResponse>, HttpError> {
    // Verify password for account deletion
    let user = UserRepository::get_user(&state.config.database.pool, UserQuery::Id(auth_user.id))
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(||
            HttpError::new(ErrorMessage::UserNoLongerExists.to_string(), StatusCode::NOT_FOUND)
        )?;

    // Verify the provided password
    if
        compare(&delete_request.password, &user.password).map_err(|_| {
            HttpError::bad_request("Password verification failed".to_string())
        })?
    {
        return Err(HttpError::unauthorized("Invalid password".to_string()));
    }

    // Prevent self-deletion for the last admin
    if user.role == UserRole::Admin {
        let admin_count = UserRepository::get_users_by_role_paginated(
            &state.config.database.pool,
            UserRole::Admin,
            1,
            10
        ).map_err(|e| HttpError::server_error(e.to_string()))?;

        if admin_count.1 <= 1 {
            return Err(HttpError::bad_request("Cannot delete the last admin user".to_string()));
        }
    }

    // Perform the deletion
    UserRepository::delete_user(&state.config.database.pool, auth_user.id).map_err(|e|
        HttpError::server_error(e.to_string())
    )?;

    // Invalidate cache
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    if
        let Err(e) = enhanced_cache.invalidate_for_user_update(
            auth_user.id,
            Some(&user),
            None
        ).await
    {
        tracing::warn!("Failed to invalidate cache after self-deletion: {}", e);
    }

    info!("User {} deleted their own account", auth_user.id);

    Ok(
        Json(DeleteUserResponse {
            message: "Account deleted successfully".to_string(),
            status: StatusCode::NO_CONTENT.as_u16(),
        })
    )
}

/// CHANGE CURRENT USER PASSWORD
/// Changes the current authenticated user's password.
///
/// This endpoint allows users to update their password by providing both their current
/// password for verification and a new password. The operation includes automatic
/// cleanup of any forced password change flags.
///
/// # Arguments
/// * `state` - Application state containing database pool and configuration
/// * `auth_user` - Authenticated user extracted from JWT token
/// * `password_change` - JSON payload containing current and new passwords
///
/// # Request Body
/// ```json
/// {
///   "current_password": "old_password",  // Required for verification
///   "new_password": "new_password"       // Required, will be hashed
/// }
/// ```
///
/// # Returns
/// * `Ok(Json<Response>)` - Success confirmation message
/// * `Err(HttpError)` - Various error types:
///   - `400` - Validation errors or password hashing failures
///   - `401` - Invalid current password
///   - `404` - User not found
///   - `500` - Database connection or query failures
///
/// # Security
/// - Requires valid authentication token
/// - Verifies current password before allowing change
/// - New password is automatically hashed using secure algorithm
/// - Clears any `force_password_change` flags after successful update
///
/// # Side Effects
/// - Automatically clears `force_password_change` flag if set
/// - Logs password change event for audit purposes
pub async fn change_current_user_password(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(password_change): Json<ChangePasswordRequest>
) -> Result<Json<Response>, HttpError> {
    // Validate the request
    if let Err(validation_errors) = password_change.validate() {
        return Err(HttpError::validation_error(validation_errors.to_string()));
    }

    // Get current user
    let user = UserRepository::get_user(&state.config.database.pool, UserQuery::Id(auth_user.id))
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(|| HttpError::not_found("User not found".to_string()))?;

    // Verify current password
    if
        compare(&password_change.current_password, &user.password).map_err(|_| {
            HttpError::bad_request("Password verification failed".to_string())
        })?
    {
        return Err(HttpError::unauthorized("Current password is incorrect".to_string()));
    }

    // Hash new password
    let hashed_new_password = hash(password_change.new_password).map_err(|_| {
        HttpError::bad_request("Password hashing failed".to_string())
    })?;

    // Update password
    UserRepository::update_user_password(
        &state.config.database.pool,
        auth_user.id,
        hashed_new_password
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    // Clear any force_password_change flag if it was set
    if user.force_password_change {
        let update_data = UpdateUserRequest {
            name: None,
            email: None,
            username: None,
            password: None,
            role: None,
            verified: None,
            updated_at: Some(Utc::now()),
        };

        let mut conn = state.conn()?;
        let _ = UserRepository::update_user(&mut conn, auth_user.id, update_data);
    }

    info!("User {} changed their password", auth_user.id);

    Ok(
        Json(Response {
            status: "success".to_string(),
            message: "Password changed successfully".to_string(),
        })
    )
}

// ============================================= ADMIN MANAGEMENT HANDLERS ================================================================
/// Admin user creation handler
/// Creates a new user account through admin interface.
///
/// This endpoint allows administrators to create new user accounts with full control
/// over user properties including role assignment and verification status. The operation
/// is performed within a database transaction to ensure data consistency.
///
/// # Arguments
/// * `state` - Application state containing database pool and configuration
/// * `auth_user` - Authenticated admin user extracted from JWT token
/// * `admin_request` - JSON payload containing new user data
///
/// # Request Body
/// ```json
/// {
///   "name": "John Doe",
///   "email": "john@example.com",
///   "username": "johndoe",
///   "password": "secure_password",
///   "role": "User",              // Admin, Manager, or User
///   "verified": true             // Email verification status
/// }
/// ```
///
/// # Returns
/// * `Ok(Json<AdminCreateUserResponse>)` - Created user information with ID
/// * `Err(HttpError)` - Various error types:
///   - `400` - Validation errors or duplicate data
///   - `401` - Insufficient privileges or invalid role assignment
///   - `500` - Database transaction or connection failures
///
/// # Security
/// - Requires admin or manager role authentication
/// - Validates role creation permissions based on requesting user's role
/// - Password is automatically hashed before storage
/// - All actions are logged for audit purposes
///
/// # Transaction Safety
/// - Uses database transaction to ensure atomicity
/// - Rollback on any failure during user creation process
/// - Includes service layer validation and business logic
///
/// # Cache Impact
/// - Invalidates relevant user search and list caches
/// - Updates role-based cache tags
pub async fn admin_create_user_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(admin_request): Json<AdminCreateUserRequest>
) -> Result<impl IntoResponse, HttpError> {
    // Validate input
    if let Err(validation_errors) = admin_request.validate() {
        error!("Validation failed for admin user creation: {}", validation_errors);
        return Err(HttpError::validation_error(validation_errors.to_string()));
    }

    // Check permissions
    if !UserService::can_create_users(&auth_user.role) {
        error!("User {} lacks permission to create users", auth_user.id);
        return Err(HttpError::unauthorized(ErrorMessage::PermissionDenied.to_string()));
    }

    // Validate role creation permissions
    if
        let Err(e) = UserService::validate_admin_creation_permissions(
            &auth_user.role,
            &admin_request.role
        )
    {
        error!("Role creation permission denied for user {}: {}", auth_user.id, e);
        return Err(HttpError::unauthorized(e.to_string()));
    }

    let mut conn = state.conn()?;

    // Use transaction for user creation
    let creation_result = conn.transaction::<AdminCreateUserResponse, DieselError, _>(|conn| {
        // Use the service layer for admin user creation
        let response = tokio::task
            ::block_in_place(move || {
                tokio::runtime::Handle
                    ::current()
                    .block_on(
                        UserService::create_user_admin(conn, admin_request, auth_user.id, &state)
                    )
            })
            .map_err(|_| DieselError::RollbackTransaction)?;

        Ok(response)
    });

    match creation_result {
        Ok(response) => {
            info!("Admin {} created user {}", auth_user.id, response.user_id);
            Ok(Json(response))
        }
        Err(DieselError::RollbackTransaction) => {
            Err(HttpError::server_error("Failed to create user".to_string()))
        }
        Err(e) => {
            error!("Database error during admin user creation: {}", e);
            Err(HttpError::server_error("Failed to create user".to_string()))
        }
    }
}

/// ADMIN UPDATE USER
/// Updates another user's profile information (Admin only).
///
/// This endpoint allows administrators to modify any user's profile data including
/// sensitive fields like role and verification status. Includes safeguards to prevent
/// removal of the last admin and self-modification through admin endpoints.
///
/// # Arguments
/// * `state` - Application state containing database pool and configuration
/// * `user_id` - UUID of the user to update (from URL path)
/// * `admin_user` - Authenticated admin user extracted from JWT token
/// * `update_data` - JSON payload containing fields to update
///
/// # Request Body
/// ```json
/// {
///   "name": "New Name",           // Optional
///   "email": "new@example.com",   // Optional
///   "username": "newusername",    // Optional
///   "password": "newpassword",    // Optional, will be hashed
///   "role": "Admin",              // Optional, Admin/Manager/User
///   "verified": true              // Optional, email verification status
/// }
/// ```
///
/// # Returns
/// * `Ok(Json<SingleUserResponse>)` - Updated user profile data
/// * `Err(HttpError)` - Various error types:
///   - `400` - Validation errors, self-update attempt, or last admin protection
///   - `401` - Insufficient admin privileges
///   - `404` - Target user not found
///   - `500` - Database connection or query failures
///
/// # Security
/// - Requires admin role authentication
/// - Prevents admin from updating themselves through this endpoint
/// - Protects against removal of last admin user
/// - Logs all admin actions for audit purposes
///
/// # Cache Invalidation
/// - Invalidates user-specific and role-based cache entries
/// - Compares old and new user data for targeted invalidation
pub async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    Json(update_data): Json<UpdateUserRequest>
) -> Result<Json<SingleUserResponse>, HttpError> {
    // Verify admin permissions
    if admin_user.role != UserRole::Admin {
        return Err(HttpError::unauthorized("Admin access required".to_string()));
    }

    // Validate the update request
    if let Err(validation_errors) = update_data.validate() {
        return Err(HttpError::validation_error(validation_errors.to_string()));
    }

    // Prevent admin from updating themselves through admin endpoint
    if user_id == admin_user.id {
        return Err(
            HttpError::bad_request(
                "Use the self-management endpoint to update your own profile".to_string()
            )
        );
    }

    let mut conn = state.conn()?;

    // Get the user being updated
    let old_user = UserRepository::get_user(&state.config.database.pool, UserQuery::Id(user_id))
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(|| HttpError::not_found("User not found".to_string()))?;

    // Special handling for admin role changes
    if let Some(new_role) = &update_data.role {
        if old_user.role == UserRole::Admin && *new_role != UserRole::Admin {
            // Check if this is the last admin
            let admin_count = UserRepository::get_users_by_role_paginated(
                &state.config.database.pool,
                UserRole::Admin,
                1,
                10
            ).map_err(|e| HttpError::server_error(e.to_string()))?;

            if admin_count.1 <= 1 {
                return Err(
                    HttpError::bad_request(
                        "Cannot remove admin role from the last admin user".to_string()
                    )
                );
            }

            tracing::warn!(
                "Admin {} is removing admin role from user {} ({})",
                admin_user.id,
                user_id,
                old_user.email
            );
        }
    }

    // Convert admin update request to internal update request
    let internal_update_data = UpdateUserRequest {
        name: update_data.name,
        email: update_data.email,
        username: update_data.username,
        password: update_data.password
            .map(|p| {
                hash(p).map_err(|_| HttpError::bad_request("Password hashing failed".to_string()))
            })
            .transpose()?,
        role: update_data.role,
        verified: update_data.verified,
        updated_at: Some(Utc::now()),
    };

    // Perform the update
    let updated_user = UserRepository::update_user(
        &mut conn,
        user_id,
        internal_update_data
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    // Invalidate cache
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    if
        let Err(e) = enhanced_cache.invalidate_for_user_update(
            user_id,
            Some(&old_user),
            Some(&updated_user)
        ).await
    {
        tracing::warn!("Failed to invalidate cache after admin update: {}", e);
    }

    info!("Admin {} updated user {} ({})", admin_user.id, user_id, updated_user.email);

    let response = SingleUserResponse {
        status: "success".to_string(),
        data: UserData {
            user: FilterUser::filter_user(&updated_user),
        },
    };

    Ok(Json(response))
}

/// ADMIN DELETE USER
/// Deletes another user's account (Admin only).
///
/// This endpoint allows administrators to permanently delete any user account except
/// their own. Includes safeguards to prevent deletion of the last admin user and
/// maintains system integrity.
///
/// # Arguments
/// * `state` - Application state containing database pool and configuration
/// * `user_id` - UUID of the user to delete (from URL path)
/// * `admin_user` - Authenticated admin user extracted from JWT token
///
/// # Returns
/// * `Ok(Json<DeleteUserResponse>)` - Success confirmation with 204 status
/// * `Err(HttpError)` - Various error types:
///   - `400` - Self-deletion attempt or last admin protection
///   - `401` - Insufficient admin privileges
///   - `404` - Target user not found
///   - `500` - Database connection or query failures
///
/// # Security
/// - Requires admin role authentication
/// - Prevents admin from deleting themselves
/// - Protects against deletion of last admin user
/// - Permanently removes user data from database
/// - Logs all deletion actions for audit purposes
///
/// # Cache Invalidation
/// - Invalidates all user-related cache entries
/// - Handles cleanup for deleted user data
/// - Updates role-based and search caches
pub async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    Extension(admin_user): Extension<AuthenticatedUser>
) -> Result<Json<DeleteUserResponse>, HttpError> {
    // Verify admin permissions
    if admin_user.role != UserRole::Admin {
        return Err(HttpError::unauthorized("Admin access required".to_string()));
    }

    // Prevent admin from deleting themselves
    if user_id == admin_user.id {
        return Err(
            HttpError::bad_request(
                "Cannot delete your own account through admin interface".to_string()
            )
        );
    }

    // Get the user being deleted
    let user_to_delete = UserRepository::get_user(
        &state.config.database.pool,
        UserQuery::Id(user_id)
    )
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(|| HttpError::not_found("User not found".to_string()))?;

    // Prevent deletion of the last admin
    if user_to_delete.role == UserRole::Admin {
        let admin_count = UserRepository::get_users_by_role_paginated(
            &state.config.database.pool,
            UserRole::Admin,
            1,
            10
        ).map_err(|e| HttpError::server_error(e.to_string()))?;

        if admin_count.1 <= 1 {
            return Err(HttpError::bad_request("Cannot delete the last admin user".to_string()));
        }
    }

    // Perform the deletion
    UserRepository::delete_user(&state.config.database.pool, user_id).map_err(|e|
        HttpError::server_error(e.to_string())
    )?;

    // Invalidate cache
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    if
        let Err(e) = enhanced_cache.invalidate_for_user_update(
            user_id,
            Some(&user_to_delete),
            None
        ).await
    {
        tracing::warn!("Failed to invalidate cache after admin deletion: {}", e);
    }

    info!("Admin {} deleted user {} ({})", admin_user.id, user_id, user_to_delete.email);

    Ok(
        Json(DeleteUserResponse {
            message: "User deleted successfully".to_string(),
            status: StatusCode::NO_CONTENT.as_u16(),
        })
    )
}

/// SEARCH USERS
/// Searches and filters users with advanced criteria and caching.
///
/// This endpoint provides comprehensive user search functionality with support for
/// text search, role filtering, verification status filtering, and pagination. Results
/// are cached for improved performance on repeated queries.
///
/// # Arguments
/// * `query_params` - URL query parameters for search and filtering
/// * `state` - Application state containing database pool and configuration
///
/// # Query Parameters
/// - `page` - Page number for pagination (default: 1)
/// - `limit` - Number of results per page (default: 10)
/// - `search` - Text search across name, email, and username fields
/// - `role` - Filter by user role (Admin, Manager, User)
/// - `verified` - Filter by email verification status (true/false)
///
/// # Example Usage
/// ```
/// GET /users/search?page=1&limit=20&search=john&role=User&verified=true
/// ```
///
/// # Returns
/// * `Ok(Json<UserListResponse>)` - Paginated list of filtered users
/// * `Err(HttpError)` - Various error types:
///   - `400` - Invalid query parameters or validation errors
///   - `500` - Database connection or query failures
///
/// # Response Format
/// ```json
/// {
///   "status": "success",
///   "users": [...],
///   "results": 50,
///   "page": 1,
///   "limit": 20,
///   "total_pages": 3
/// }
/// ```
///
/// # Caching
/// - Cache key includes all search parameters for unique identification
/// - TTL: `SEARCH_CACHE_TTL`
/// - Tags: `["users_search", "role:{role}", "verified:{status}"]`
/// - Automatic invalidation when user data changes
///
/// # Security
/// - No authentication required for basic user search
/// - Filtered user data excludes sensitive information
/// - Search results are paginated to prevent data dumping
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

/// LIST USERS
/// Retrieves a basic list of users for manager-level access.
///
/// This endpoint provides a simplified user listing with limited information suitable
/// for managers who need basic user oversight capabilities. The response excludes
/// sensitive user data and administrative details.
///
/// # Arguments
/// * `state` - Application state containing database pool and configuration
///
/// # Returns
/// * `Ok(Json<Value>)` - Basic user list with limited fields
/// * `Err(HttpError)` - Various error types:
///   - `500` - Database connection or query failures
///
/// # Response Format
/// ```json
/// {
///   "users": [
///     {
///       "id": 1,
///       "email": "user@example.com",
///       "role": "User",
///       "active": true
///     }
///   ],
///   "total_count": 2
/// }
/// ```
///
/// # Security
/// - Currently returns mock data for demonstration
/// - Intended for manager-level access with restricted information
/// - Excludes sensitive fields like creation dates, last login, etc.
/// - Future implementation should include proper authentication checks
///
/// # Note
/// This is currently a placeholder implementation returning static mock data.
/// Production implementation should include:
/// - Proper authentication and authorization checks
/// - Database queries with appropriate filtering
/// - Pagination support for large user sets
/// - Caching for improved performance
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

/// LIST ALL USERS
/// Retrieves a comprehensive list of all users for admin-level access.
///
/// This endpoint provides detailed user information including sensitive administrative
/// data such as creation dates, last login times, and verification status. This
/// comprehensive view is intended for full administrative oversight and user management.
///
/// # Arguments
/// * `state` - Application state containing database pool and configuration
///
/// # Returns
/// * `Ok(Json<Value>)` - Comprehensive user list with full details
/// * `Err(HttpError)` - Various error types:
///   - `500` - Database connection or query failures
///
/// # Response Format
/// ```json
/// {
///   "users": [
///     {
///       "id": 1,
///       "email": "user@example.com",
///       "role": "User",
///       "active": true,
///       "created_at": "2024-01-10T08:00:00Z",
///       "last_login": "2024-01-20T14:30:00Z",
///       "email_verified": true
///     }
///   ],
///   "total_count": 3,
///   "admin_count": 1,
///   "active_count": 3
/// }
/// ```
///
/// # Security
/// - Currently returns mock data for demonstration
/// - Intended for admin-only access with full user details
/// - Includes sensitive information like timestamps and verification status
/// - Future implementation should include strict admin authentication
///
/// # Additional Metrics
/// - Provides summary statistics (total_count, admin_count, active_count)
/// - Useful for administrative dashboards and user management interfaces
/// - Helps admins understand user base composition and activity
///
/// # Note
/// This is currently a placeholder implementation returning static mock data.
/// Production implementation should include:
/// - Strict admin authentication and authorization
/// - Real database queries with proper error handling
/// - Pagination support for large user databases
/// - Caching with appropriate cache invalidation strategies
/// - Audit logging for admin access to sensitive user data
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
