// pub mod aws;
pub mod database;
pub mod cache;
pub mod logging;
pub mod email;

// use aws::AwsConfig;
pub use database::{ DatabaseConfig, ConfigError };
use cache::CacheConfig;

#[derive(Debug, Clone)]
pub struct Config {
    //     pub aws: AwsConfig,
    pub database: DatabaseConfig,
    pub cache: CacheConfig,
}

impl Config {
    pub async fn new() -> Result<Self, ConfigError> {
        let database_config = DatabaseConfig::new()?;
        let cache_config = CacheConfig::new(&database_config.redis_url)?;
        Ok(Self {
            database: database_config,
            cache: cache_config,
        })
    }
}
