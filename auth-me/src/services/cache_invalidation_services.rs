use std::collections::HashSet;

use redis::Commands;
use serde::{ Deserialize, Serialize };
use tracing::{ error, info };

use crate::{
    config::ConfigError,
    services::cache_services::CacheService,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheKeyMetadata {
    pub key: String,
    pub tags: HashSet<String>,
    pub created_at: i64,
    pub ttl: u64,
}

pub struct CacheInvalidationService {
    cache_service: CacheService,
}

impl CacheInvalidationService {
    pub fn new(cache_service: CacheService) -> Self {
        Self { cache_service }
    }

    /// Register a cache key with its associated tags for later invalidation
    pub async fn register_cache_key(&self, key: &str, tags: Vec<String>, ttl: u64) -> bool {
        let metadata = CacheKeyMetadata {
            key: key.to_string(),
            tags: tags.into_iter().collect(),
            created_at: chrono::Utc::now().timestamp(),
            ttl,
        };

        // Store metadata for this cache key
        let metadata_key = format!("cache_meta:{}", key);
        let success = self.cache_service.set(&metadata_key, &metadata, ttl + 300).await; // Store metadata slightly longer

        if success {
            // Add this key to each tag's key list
            for tag in &metadata.tags {
                let tag_key = format!("cache_tag:{}", tag);
                if let Ok(mut conn) = self.cache_service.cache_config.get_connection().await {
                    let _: Result<(), _> = conn.sadd(&tag_key, key);
                    if let Ok(ttl_i64) = (ttl + 300).try_into() {
                        let _: Result<(), _> = conn.expire(&tag_key, ttl_i64);
                    } else {
                        error!("TTL value too large to convert to i64: {}", ttl + 300);
                    }
                }
            }
        }

        success
    }

    /// Invalidate all cache keys associated with specific tags
    pub async fn invalidate_by_tags(&self, tags: &[String]) -> Result<usize, ConfigError> {
        let mut invalidated_count = 0;
        let mut keys_to_delete = HashSet::new();

        for tag in tags {
            let tag_key = format!("cache_tag:{}", tag);

            if let Ok(mut conn) = self.cache_service.cache_config.get_connection().await {
                // Get all keys associated with this tag
                match conn.smembers::<String, Vec<String>>(tag_key.clone()) {
                    Ok(tagged_keys) => {
                        for key in tagged_keys {
                            keys_to_delete.insert(key);
                        }
                        // Clean up the tag key itself
                        let _: Result<i32, _> = conn.del(&tag_key);
                    }
                    Err(e) => {
                        error!("Failed to get members for tag {}: {}", tag, e);
                    }
                }
            }
        }

        // Delete all collected keys
        for key in &keys_to_delete {
            if self.cache_service.delete(key).await {
                invalidated_count += 1;
                // Also delete the metadata
                let metadata_key = format!("cache_meta:{}", key);
                self.cache_service.delete(&metadata_key).await;
            }
        }

        info!("Invalidated {} cache keys for tags: {:?}", invalidated_count, tags);
        Ok(invalidated_count)
    }

    /// Invalidate cache keys using pattern matching (use sparingly as it's expensive)
    pub async fn invalidate_by_pattern(&self, pattern: &str) -> Result<usize, ConfigError> {
        if let Ok(mut conn) = self.cache_service.cache_config.get_connection().await {
            match conn.keys::<String, Vec<String>>(pattern.to_string()) {
                Ok(keys) => {
                    let mut invalidated_count = 0;
                    for key in keys {
                        if self.cache_service.delete(&key).await {
                            invalidated_count += 1;
                            // Also delete metadata
                            let metadata_key = format!("cache_meta:{}", key);
                            self.cache_service.delete(&metadata_key).await;
                        }
                    }
                    info!(
                        "Invalidated {} cache keys matching pattern: {}",
                        invalidated_count,
                        pattern
                    );
                    Ok(invalidated_count)
                }
                Err(e) => {
                    error!("Failed to get keys for pattern {}: {}", pattern, e);
                    Err(ConfigError::Redis(e))
                }
            }
        } else {
            Err(ConfigError::RedisError)
        }
    }

    /// Clean up expired cache metadata
    pub async fn cleanup_expired_metadata(&self) -> Result<usize, ConfigError> {
        let current_time = chrono::Utc::now().timestamp();
        let mut cleaned_count = 0;

        if let Ok(mut conn) = self.cache_service.cache_config.get_connection().await {
            // Get all metadata keys
            match conn.keys::<String, Vec<String>>("cache_meta:*".to_string()) {
                Ok(metadata_keys) => {
                    for metadata_key in metadata_keys {
                        if
                            let Some(metadata) = self.cache_service.get::<CacheKeyMetadata>(
                                &metadata_key
                            ).await
                        {
                            // Check if the cache key has expired
                            if current_time > metadata.created_at + (metadata.ttl as i64) {
                                // Remove from tag associations
                                for tag in &metadata.tags {
                                    let tag_key = format!("cache_tag:{}", tag);
                                    let _: Result<i32, _> = conn.srem(&tag_key, &metadata.key);
                                }
                                // Delete the metadata
                                if self.cache_service.delete(&metadata_key).await {
                                    cleaned_count += 1;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get metadata keys: {}", e);
                    return Err(ConfigError::Redis(e));
                }
            }
        }

        if cleaned_count > 0 {
            info!("Cleaned up {} expired cache metadata entries", cleaned_count);
        }
        Ok(cleaned_count)
    }
}
