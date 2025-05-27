use axum::{ extract::{ Query, State}, Json, http::StatusCode };
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use crate::{
    config::ConfigError,
    dto::user_dtos::{
        AdvancedSearchQuery,
        AdvancedUserFilters,
        BulkOperationResponse,
        BulkRoleUpdateRequest,
        CacheInvalidationRequest,
        CacheInvalidationResponse,
        CacheStatisticsResponse,
        CleanupResponse,
        FilterUser,
        UserListResponse,
        UserQuery,
        UserStatisticsResponse,
        VerifyTokenRequest,
    },
    errors::HttpError,
    models::User,
    repositories::user_repository::UserRepository,
    services::{ cache_services::CacheService, enhanced_cache_services::EnhancedCacheService },
    AppState,
};

/// BULK DELETE USERS WITH CACHE INVALIDATION
pub async fn bulk_delete_users(
    State(state): State<Arc<AppState>>,
    Json(user_ids): Json<Vec<Uuid>>
) -> Result<Json<BulkOperationResponse>, HttpError> {
    if user_ids.is_empty() {
        return Err(HttpError::bad_request("No user IDs provided".to_string()));
    }

    // Perform bulk deletion (implement in repository)
    let deleted_count = UserRepository::bulk_delete_users(
        &state.config.database.pool,
        &user_ids
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    // Invalidate cache for all affected users
    if let Err(e) = enhanced_cache.invalidate_bulk_users_cache(&user_ids).await {
        tracing::warn!("Failed to invalidate cache after bulk user deletion: {}", e);
    }

    let response = BulkOperationResponse {
        status: "success".to_string(),
        affected_count: deleted_count,
        message: format!("Successfully deleted {} users", deleted_count),
    };

    Ok(Json(response))
}

/// VERIFY USER TOKEN WITH CACHE INVALIDATION
pub async fn verify_user_token(
    State(state): State<Arc<AppState>>,
    Json(token_data): Json<VerifyTokenRequest>
) -> Result<StatusCode, HttpError> {
    // Find user by token first
    let user = UserRepository::get_user(
        &state.config.database.pool,
        UserQuery::Token(token_data.token.clone())
    )
        .map_err(|e| HttpError::server_error(e.to_string()))?
        .ok_or_else(||
            HttpError::new("Invalid or expired token".to_string(), StatusCode::BAD_REQUEST)
        )?;

    // Verify the token
    UserRepository::verify_token(&state.config.database.pool, &token_data.token).map_err(|e| {
        match e {
            ConfigError::NotFound =>
                HttpError::new("Invalid or expired token".to_string(), StatusCode::BAD_REQUEST),
            _ => HttpError::server_error(e.to_string()),
        }
    })?;

    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    // Invalidate cache for the verified user (verification status changed)
    if let Err(e) = enhanced_cache.invalidate_user_cache(user.id).await {
        tracing::warn!("Failed to invalidate cache after user verification: {}", e);
    }

    // Also invalidate verification-specific caches
    if let Err(e) = enhanced_cache.invalidate_verification_cache(true).await {
        tracing::warn!("Failed to invalidate verification cache: {}", e);
    }

    Ok(StatusCode::OK)
}

/// Background task for periodic cache cleanup
pub async fn periodic_cache_cleanup(enhanced_cache: Arc<EnhancedCacheService>) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(300)).await; // Every 5 minutes

        if let Err(e) = enhanced_cache.periodic_cleanup().await {
            tracing::error!("Failed to perform periodic cache cleanup: {}", e);
        }
    }
}

/// GET USER STATISTICS WITH CACHING
pub async fn get_user_statistics(State(state): State<Arc<AppState>>) -> Result<
    Json<UserStatisticsResponse>,
    HttpError
> {
    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);
    let cache_key = "user_statistics".to_string();

    // Try cache first (short TTL since stats change frequently)
    if
        let Some(cached_response) = enhanced_cache.cache_service.get::<UserStatisticsResponse>(
            &cache_key
        ).await
    {
        return Ok(Json(cached_response));
    }

    // Get from database
    let stats = UserRepository::get_user_statistics(&state.config.database.pool).map_err(|e|
        HttpError::server_error(e.to_string())
    )?;

    let response = UserStatisticsResponse {
        status: "success".to_string(),
        data: stats,
    };

    // Cache with multiple tags since stats depend on all user data
    let tags = vec![
        "user_statistics".to_string(),
        "users_list".to_string(),
        "role:Admin".to_string(),
        "role:Moderator".to_string(),
        "role:User".to_string(),
        "verified:true".to_string(),
        "verified:false".to_string()
    ];

    enhanced_cache.set_with_tags(&cache_key, &response, 120, tags).await; // 2 minutes TTL

    Ok(Json(response))
}

/// ADVANCED SEARCH WITH SOPHISTICATED CACHING
pub async fn advanced_search_users(
    Query(query_params): Query<AdvancedSearchQuery>,
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

    // Create a complex cache key that includes all search parameters
    let cache_key = format!(
        "advanced_search:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        page,
        limit,
        query_params.search_term.as_deref().unwrap_or(""),
        query_params.roles
            .as_ref()
            .map(|r| format!("{:?}", r))
            .unwrap_or_default(),
        query_params.verified.map(|v| v.to_string()).unwrap_or_default(),
        query_params.created_after.map(|d| d.and_utc().timestamp()).unwrap_or(0),
        query_params.created_before.map(|d| d.and_utc().timestamp()).unwrap_or(0),
        query_params.sort_by
            .as_ref()
            .map(|s| format!("{:?}", s))
            .unwrap_or_default(),
        query_params.sort_desc.unwrap_or(false)
    );

    // Try cache first
    if
        let Some(cached_response) = enhanced_cache.cache_service.get::<UserListResponse>(
            &cache_key
        ).await
    {
        return Ok(Json(cached_response));
    }

    // Build comprehensive tags for cache invalidation before moving query_params
    let mut tags = vec!["users_search".to_string(), "advanced_search".to_string()];

    if let Some(roles) = &query_params.roles {
        for role in roles {
            tags.push(format!("role:{:?}", role));
        }
    }

    if let Some(verified) = query_params.verified {
        tags.push(format!("verified:{}", verified));
    }

    // Convert to internal filter structure
    let filters = AdvancedUserFilters {
        search_term: query_params.search_term,
        roles: query_params.roles,
        verified: query_params.verified,
        created_after: query_params.created_after,
        created_before: query_params.created_before,
        sort_by: query_params.sort_by,
        sort_desc: query_params.sort_desc,
    };

    // Get from database
    let (users, total_count) = UserRepository::advanced_search_users(
        &state.config.database.pool,
        filters,
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

    enhanced_cache.set_with_tags(&cache_key, &response, 45, tags).await; // 45 seconds TTL

    Ok(Json(response))
}

/// BULK UPDATE USER ROLES WITH CACHE INVALIDATION
pub async fn bulk_update_user_roles(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BulkRoleUpdateRequest>
) -> Result<Json<BulkOperationResponse>, HttpError> {
    request.validate().map_err(|e| HttpError::bad_request(format!("Validation error: {}", e)))?;

    if request.user_ids.is_empty() {
        return Err(HttpError::bad_request("No user IDs provided".to_string()));
    }

    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    // Get affected users before update for cache invalidation
    let affected_users: Vec<User> = request.user_ids
        .iter()
        .filter_map(|&user_id| {
            UserRepository::get_user(
                &state.config.database.pool,
                crate::dto::user_dtos::UserQuery::Id(user_id)
            )
                .ok()
                .flatten()
        })
        .collect();

    // Perform bulk role update
    let updated_count = UserRepository::bulk_update_user_roles(
        &state.config.database.pool,
        &request.user_ids,
        request.new_role
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    // Sophisticated cache invalidation based on role changes
    let mut invalidation_tags = vec![
        "users_list".to_string(),
        "users_search".to_string(),
        "advanced_search".to_string(),
        "user_statistics".to_string(),
        format!("role:{:?}", request.new_role) // New role
    ];

    // Add tags for old roles
    for user in &affected_users {
        invalidation_tags.push(format!("role:{:?}", user.role));
        invalidation_tags.push(format!("user:{}", user.id));
    }

    // Remove duplicates
    invalidation_tags.sort();
    invalidation_tags.dedup();

    if
        let Err(e) = enhanced_cache.invalidation_service.invalidate_by_tags(
            &invalidation_tags
        ).await
    {
        tracing::warn!("Failed to invalidate cache after bulk role update: {}", e);
    }

    let response = BulkOperationResponse {
        status: "success".to_string(),
        affected_count: updated_count,
        message: format!(
            "Successfully updated roles for {} users to {:?}",
            updated_count,
            request.new_role
        ),
    };

    Ok(Json(response))
}

/// BULK VERIFY USERS WITH CACHE INVALIDATION
pub async fn bulk_verify_users(
    State(state): State<Arc<AppState>>,
    Json(user_ids): Json<Vec<Uuid>>
) -> Result<Json<BulkOperationResponse>, HttpError> {
    if user_ids.is_empty() {
        return Err(HttpError::bad_request("No user IDs provided".to_string()));
    }

    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    // Perform bulk verification
    let verified_count = UserRepository::bulk_verify_users(
        &state.config.database.pool,
        &user_ids
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    // Invalidate verification-related caches
    let invalidation_tags = vec![
        "users_list".to_string(),
        "users_search".to_string(),
        "advanced_search".to_string(),
        "user_statistics".to_string(),
        "verified:false".to_string(), // Old status
        "verified:true".to_string() // New status
    ];

    // Add individual user tags
    let mut all_tags = invalidation_tags;
    for user_id in &user_ids {
        all_tags.push(format!("user:{}", user_id));
    }

    if let Err(e) = enhanced_cache.invalidation_service.invalidate_by_tags(&all_tags).await {
        tracing::warn!("Failed to invalidate cache after bulk verification: {}", e);
    }

    let response = BulkOperationResponse {
        status: "success".to_string(),
        affected_count: verified_count,
        message: format!("Successfully verified {} users", verified_count),
    };

    Ok(Json(response))
}

/// CLEANUP EXPIRED TOKENS WITH CACHE INVALIDATION
pub async fn cleanup_expired_tokens(State(state): State<Arc<AppState>>) -> Result<
    Json<CleanupResponse>,
    HttpError
> {
    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    // Get expired users before cleanup for cache invalidation
    let expired_users = UserRepository::get_expired_unverified_users(
        &state.config.database.pool
    ).map_err(|e| HttpError::server_error(e.to_string()))?;

    // Perform cleanup
    let cleaned_count = UserRepository::cleanup_expired_tokens(&state.config.database.pool).map_err(
        |e| HttpError::server_error(e.to_string())
    )?;

    // Invalidate cache for affected users
    if !expired_users.is_empty() {
        let mut invalidation_tags = vec![
            "users_list".to_string(),
            "users_search".to_string(),
            "user_statistics".to_string()
        ];

        for user in &expired_users {
            invalidation_tags.push(format!("user:{}", user.id));
        }

        if
            let Err(e) = enhanced_cache.invalidation_service.invalidate_by_tags(
                &invalidation_tags
            ).await
        {
            tracing::warn!("Failed to invalidate cache after token cleanup: {}", e);
        }
    }

    let response = CleanupResponse {
        status: "success".to_string(),
        cleaned_count,
        message: format!("Cleaned up {} expired verification tokens", cleaned_count),
    };

    Ok(Json(response))
}

/// CACHE MANAGEMENT ENDPOINTS (for admin use)

/// GET CACHE STATISTICS
pub async fn get_cache_statistics(State(_state): State<Arc<AppState>>) -> Result<
    Json<CacheStatisticsResponse>,
    HttpError
> {
    // This would require implementing cache statistics in the Redis service
    // For now, return a placeholder
    let response = CacheStatisticsResponse {
        status: "success".to_string(),
        message: "Cache statistics endpoint - implement based on Redis setup".to_string(),
    };

    Ok(Json(response))
}

/// INVALIDATE CACHE BY PATTERN (admin only)
pub async fn invalidate_cache_pattern(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CacheInvalidationRequest>
) -> Result<Json<CacheInvalidationResponse>, HttpError> {
    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    let invalidated_count = enhanced_cache.invalidation_service
        .invalidate_by_pattern(&request.pattern).await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = CacheInvalidationResponse {
        status: "success".to_string(),
        invalidated_count,
        message: format!(
            "Invalidated {} cache keys matching pattern: {}",
            invalidated_count,
            request.pattern
        ),
    };

    Ok(Json(response))
}

/// MANUAL CACHE CLEANUP
pub async fn manual_cache_cleanup(State(state): State<Arc<AppState>>) -> Result<
    Json<CleanupResponse>,
    HttpError
> {
    // Create cache service and enhanced cache service from config
    let cache_service = CacheService::new(state.config.cache.clone());
    let enhanced_cache = EnhancedCacheService::new(cache_service);

    let cleaned_count = enhanced_cache
        .periodic_cleanup().await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = CleanupResponse {
        status: "success".to_string(),
        cleaned_count,
        message: format!("Manually cleaned up {} expired cache entries", cleaned_count),
    };

    Ok(Json(response))
}
