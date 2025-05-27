use crate::{
    config::ConfigError,
    services::{cache_services::CacheService, cache_invalidation_services::CacheInvalidationService},
    models::{ User, UserRole },
};
use serde::Serialize;
use uuid::Uuid;

/// Enhanced cache service with invalidation capabilities
pub struct EnhancedCacheService {
    pub cache_service: CacheService,
    pub invalidation_service: CacheInvalidationService,
}

impl EnhancedCacheService {
    pub fn new(cache_service: CacheService) -> Self {
        let invalidation_service = CacheInvalidationService::new(cache_service.clone());
        Self {
            cache_service,
            invalidation_service,
        }
    }

    /// Set cache with tags for sophisticated invalidation
    pub async fn set_with_tags<T>(
        &self,
        key: &str,
        value: &T,
        ttl_seconds: u64,
        tags: Vec<String>
    ) -> bool
        where T: Serialize
    {
        // Set the cache value
        let success = self.cache_service.set(key, value, ttl_seconds).await;

        if success {
            // Register the key with its tags
            self.invalidation_service.register_cache_key(key, tags, ttl_seconds).await;
        }

        success
    }

    /// User-specific cache invalidation methods
    pub async fn invalidate_user_cache(&self, user_id: Uuid) -> Result<usize, ConfigError> {
        let tags = vec![
            format!("user:{}", user_id),
            "users_list".to_string(),
            "users_search".to_string()
        ];

        self.invalidation_service.invalidate_by_tags(&tags).await
    }

    pub async fn invalidate_users_list_cache(&self) -> Result<usize, ConfigError> {
        let tags = vec!["users_list".to_string(), "users_search".to_string()];

        self.invalidation_service.invalidate_by_tags(&tags).await
    }

    pub async fn invalidate_role_specific_cache(
        &self,
        role: UserRole
    ) -> Result<usize, ConfigError> {
        let tags = vec![
            format!("role:{:?}", role),
            "users_list".to_string(),
            "users_search".to_string()
        ];

        self.invalidation_service.invalidate_by_tags(&tags).await
    }

    pub async fn invalidate_verification_cache(
        &self,
        is_verified: bool
    ) -> Result<usize, ConfigError> {
        let tags = vec![
            format!("verified:{}", is_verified),
            "users_list".to_string(),
            "users_search".to_string()
        ];

        self.invalidation_service.invalidate_by_tags(&tags).await
    }

    /// Comprehensive user update cache invalidation
    pub async fn invalidate_for_user_update(
        &self,
        user_id: Uuid,
        old_user: Option<&User>,
        new_user: Option<&User>
    ) -> Result<usize, ConfigError> {
        let mut tags = vec![
            format!("user:{}", user_id),
            "users_list".to_string(),
            "users_search".to_string()
        ];

        // Add role-specific tags if role changed
        if let (Some(old), Some(new)) = (old_user, new_user) {
            if old.role != new.role {
                tags.push(format!("role:{:?}", old.role));
                tags.push(format!("role:{:?}", new.role));
            }

            if old.verified != new.verified {
                tags.push(format!("verified:{}", old.verified));
                tags.push(format!("verified:{}", new.verified));
            }
        }

        self.invalidation_service.invalidate_by_tags(&tags).await
    }

    /// Bulk user operations cache invalidation
    pub async fn invalidate_bulk_users_cache(
        &self,
        user_ids: &[Uuid]
    ) -> Result<usize, ConfigError> {
        let mut tags = vec!["users_list".to_string(), "users_search".to_string()];

        // Add individual user tags
        for user_id in user_ids {
            tags.push(format!("user:{}", user_id));
        }

        self.invalidation_service.invalidate_by_tags(&tags).await
    }

    /// Schedule periodic cleanup (call this in a background task)
    pub async fn periodic_cleanup(&self) -> Result<usize, ConfigError> {
        self.invalidation_service.cleanup_expired_metadata().await
    }
}
