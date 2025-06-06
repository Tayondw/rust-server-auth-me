use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::{
    config::email::EmailConfig,
    dto::email_dtos::*,
    services::enhanced_cache_services::EnhancedCacheService,
};

pub struct TemplateCache {
    redis_cache: Option<Arc<EnhancedCacheService>>,
    memory_cache: Arc<RwLock<HashMap<String, MemoryCachedTemplate>>>,
    config: EmailConfig,
}

impl TemplateCache {
    pub fn new(config: EmailConfig, redis_cache: Option<Arc<EnhancedCacheService>>) -> Self {
        Self {
            redis_cache,
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    pub async fn get_template(&self, template_path: &str) -> Result<String, String> {
        let cache_key = format!("email_template:{}", template_path);

        // Try Redis first
        if let Some(redis_cache) = &self.redis_cache {
            if
                let Some(cached_template) = redis_cache.cache_service.get::<CachedEmailTemplate>(
                    &cache_key
                ).await
            {
                self.store_in_memory(template_path, &cached_template.content).await;
                return Ok(cached_template.content);
            }
        }

        // Try memory cache
        {
            let memory_cache = self.memory_cache.read().await;
            if let Some(cached) = memory_cache.get(template_path) {
                if !cached.is_expired() {
                    return Ok(cached.content.clone());
                }
            }
        }
        // Load from file
        let content = self.load_from_file(template_path).await?;
        self.store_in_all_caches(template_path, &content).await?;
        Ok(content)
    }

    async fn load_from_file(&self, template_path: &str) -> Result<String, String> {
        tokio::fs
            ::read_to_string(template_path).await
            .map_err(|e| format!("Failed to read template {}: {}", template_path, e))
    }

    async fn store_in_all_caches(&self, template_path: &str, content: &str) -> Result<(), String> {
        self.store_in_memory(template_path, content).await;

        if let Some(redis_cache) = &self.redis_cache {
            let cache_key = format!("email_template:{}", template_path);
            let cached_template = CachedEmailTemplate::new(
                content.to_string(),
                template_path.to_string()
            );

            let tags = vec![
                "email_templates".to_string(),
                format!("template_file:{}", template_path)
            ];

            redis_cache.set_with_tags(
                &cache_key,
                &cached_template,
                self.config.redis_template_ttl,
                tags
            ).await;
        }

        Ok(())
    }

    async fn store_in_memory(&self, template_path: &str, content: &str) {
        let mut memory_cache = self.memory_cache.write().await;
        let cached_template = MemoryCachedTemplate::new(
            content.to_string(),
            self.config.template_cache_ttl
        );
        memory_cache.insert(template_path.to_string(), cached_template);
    }

    pub async fn invalidate_template(&self, template_path: &str) -> Result<usize, String> {
        {
            let mut memory_cache = self.memory_cache.write().await;
            memory_cache.remove(template_path);
        }

        if let Some(redis_cache) = &self.redis_cache {
            let tags = vec![format!("template_file:{}", template_path)];
            return redis_cache.invalidation_service
                .invalidate_by_tags(&tags).await
                .map_err(|e| format!("Redis invalidation failed: {:?}", e));
        }

        Ok(1)
    }

    pub async fn invalidate_all(&self) -> Result<usize, String> {
        {
            let mut memory_cache = self.memory_cache.write().await;
            memory_cache.clear();
        }

        if let Some(redis_cache) = &self.redis_cache {
            let tags = vec!["email_templates".to_string()];
            return redis_cache.invalidation_service
                .invalidate_by_tags(&tags).await
                .map_err(|e| format!("Redis invalidation failed: {:?}", e));
        }

        Ok(0)
    }

    pub async fn cleanup_memory(&self) {
        let mut memory_cache = self.memory_cache.write().await;
        memory_cache.retain(|_, template| !template.is_expired());
    }

    pub async fn get_stats(&self) -> EnhancedCacheStats {
        let memory_cache = self.memory_cache.read().await;
        let memory_total = memory_cache.len();
        let memory_expired = memory_cache
            .values()
            .filter(|t| t.is_expired())
            .count();

        EnhancedCacheStats {
            memory_total_entries: memory_total,
            memory_expired_entries: memory_expired,
            memory_active_entries: memory_total - memory_expired,
            redis_enabled: self.redis_cache.is_some(),
        }
    }
}
