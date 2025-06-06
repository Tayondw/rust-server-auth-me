use serde::{ Serialize, Deserialize };
use std::time::Instant;

/// Email request structure for batch processing
#[derive(Clone, Debug)]
pub struct EmailRequest {
    pub to_email: String,
    pub subject: String,
    pub template_path: String,
    pub placeholders: Vec<(String, String)>,
}

/// Enhanced cache statistics
#[derive(Debug)]
pub struct EnhancedCacheStats {
    pub memory_total_entries: usize,
    pub memory_expired_entries: usize,
    pub memory_active_entries: usize,
    pub redis_enabled: bool,
}

/// Template data structure for Redis storage
#[derive(Serialize, Deserialize, Clone)]
pub struct CachedEmailTemplate {
    pub content: String,
    pub file_path: String,
    pub cached_at: u64,
    pub file_hash: Option<String>,
}

impl CachedEmailTemplate {
    pub fn new(content: String, file_path: String) -> Self {
        Self {
            content,
            file_path,
            cached_at: std::time::SystemTime
                ::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            file_hash: None,
        }
    }
}

/// In-memory cache entry
#[derive(Clone)]
pub struct MemoryCachedTemplate {
    pub content: String,
    pub cached_at: Instant,
    pub ttl: std::time::Duration,
}

impl MemoryCachedTemplate {
    pub fn new(content: String, ttl: std::time::Duration) -> Self {
        Self {
            content,
            cached_at: Instant::now(),
            ttl,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}
