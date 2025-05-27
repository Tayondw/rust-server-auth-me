use redis::Commands;
use serde::{ Deserialize, Serialize };
use tracing::{ error, info };

use crate::config::cache::CacheConfig;

#[derive(Clone)]
pub struct CacheService {
    pub cache_config: CacheConfig,
}

impl CacheService {
    pub fn new(cache_config: CacheConfig) -> Self {
        Self { cache_config }
    }

    pub async fn get<T>(&self, key: &str) -> Option<T> where T: for<'de> Deserialize<'de> {
        match self.cache_config.get_connection().await {
            Ok(mut conn) => {
                match conn.get::<&str, String>(key) {
                    Ok(value) =>
                        match serde_json::from_str::<T>(&value) {
                            Ok(data) => {
                                info!("Cache hit for key: {}", key);
                                Some(data)
                            }
                            Err(e) => {
                                error!("Failed to deserialize cached value for key {}: {}", key, e);
                                None
                            }
                        }
                    Err(_) => {
                        info!("Cache miss for key: {}", key);
                        None
                    }
                }
            }
            Err(e) => {
                error!("Failed to get Redis connection: {}", e);
                None
            }
        }
    }

    pub async fn set<T>(&self, key: &str, value: &T, ttl_seconds: u64) -> bool where T: Serialize {
        match self.cache_config.get_connection().await {
            Ok(mut conn) => {
                match serde_json::to_string(value) {
                    Ok(serialized) => {
                        match conn.set_ex::<&str, String, ()>(key, serialized, ttl_seconds) {
                            Ok(_) => {
                                info!("Cached value for key: {} with TTL: {}s", key, ttl_seconds);
                                true
                            }
                            Err(e) => {
                                error!("Failed to cache value for key {}: {}", key, e);
                                false
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize value for key {}: {}", key, e);
                        false
                    }
                }
            }
            Err(e) => {
                error!("Failed to get Redis connection: {}", e);
                false
            }
        }
    }

    pub async fn delete(&self, key: &str) -> bool {
        match self.cache_config.get_connection().await {
            Ok(mut conn) => {
                match conn.del::<&str, i32>(key) {
                    Ok(_) => {
                        info!("Deleted cache key: {}", key);
                        true
                    }
                    Err(e) => {
                        error!("Failed to delete cache key {}: {}", key, e);
                        false
                    }
                }
            }
            Err(e) => {
                error!("Failed to get Redis connection: {}", e);
                false
            }
        }
    }
}
