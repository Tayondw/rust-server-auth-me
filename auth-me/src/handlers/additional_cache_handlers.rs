use axum::{ extract::{ Query, State }, Json };
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use crate::{
    models::User,
    repositories::user_repository::UserRepository,
    dto::user_dtos::{
        FilterUser,
        UserListResponse,
        BulkRoleUpdateRequest,
        BulkOperationResponse,
        AdvancedUserFilters,
        UserStatisticsResponse,
        AdvancedSearchQuery,
        CleanupResponse,
        CacheInvalidationResponse,
        CacheInvalidationRequest,
        CacheStatisticsResponse,
    },
    AppState,
    errors::HttpError,
    services::{ enhanced_cache_services::EnhancedCacheService, cache_services::CacheService },
};

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
        query_params.created_after.map(|d| d.timestamp()).unwrap_or(0),
        query_params.created_before.map(|d| d.timestamp()).unwrap_or(0),
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
    // This would require implementing cache statistics in your Redis service
    // For now, return a placeholder
    let response = CacheStatisticsResponse {
        status: "success".to_string(),
        message: "Cache statistics endpoint - implement based on your Redis setup".to_string(),
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
