use std::time::Duration;

/// Enhanced email configuration with Redis caching
#[derive(Clone)]
pub struct EmailConfig {
    pub smtp_username: String,
    pub smtp_from_address: String,
    pub smtp_password: String,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub max_pool_size: usize,
    pub template_cache_ttl: Duration,
    pub connection_timeout: Duration,
    pub redis_template_ttl: u64, // TTL for Redis cache in seconds
    pub enable_redis_cache: bool,
}

impl EmailConfig {
    pub fn from_env() -> Result<Self, String> {
        Ok(EmailConfig {
            smtp_username: std::env
                ::var("SMTP_USERNAME")
                .map_err(|_| "Missing SMTP_USERNAME env variable")?,
            smtp_from_address: std::env
                ::var("SMTP_FROM_ADDRESS")
                .map_err(|_| "Missing SMTP_FROM_ADDRESS env variable")?,
            smtp_password: std::env
                ::var("SMTP_PASSWORD")
                .map_err(|_| "Missing SMTP_PASSWORD env variable")?,
            smtp_server: std::env
                ::var("SMTP_SERVER")
                .map_err(|_| "Missing SMTP_SERVER env variable")?,
            smtp_port: std::env
                ::var("SMTP_PORT")
                .map_err(|_| "Missing SMTP_PORT env variable")?
                .parse()
                .map_err(|_| "Invalid SMTP_PORT value")?,
            max_pool_size: std::env
                ::var("SMTP_POOL_SIZE")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            template_cache_ttl: Duration::from_secs(
                std::env
                    ::var("TEMPLATE_CACHE_TTL_SECONDS")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()
                    .unwrap_or(3600)
            ),
            connection_timeout: Duration::from_secs(30),
            redis_template_ttl: std::env
                ::var("REDIS_TEMPLATE_TTL_SECONDS")
                .unwrap_or_else(|_| "7200".to_string()) // 2 hours default
                .parse()
                .unwrap_or(7200),
            enable_redis_cache: std::env
                ::var("ENABLE_REDIS_TEMPLATE_CACHE")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.smtp_username.is_empty() {
            return Err("SMTP username cannot be empty".to_string());
        }
        if self.smtp_server.is_empty() {
            return Err("SMTP server cannot be empty".to_string());
        }
        if self.max_pool_size == 0 {
            return Err("Pool size must be greater than 0".to_string());
        }
        Ok(())
    }
}
