// pub mod aws;
pub mod database;

// use aws::AwsConfig;
pub use database::{ DatabaseConfig, ConfigError };

#[derive(Debug, Clone)]
pub struct Config {
//     pub aws: AwsConfig,
    pub database: DatabaseConfig,
}

impl Config {
    pub async fn new() -> Result<Self, ConfigError> {
        Ok(Self {
            // aws: AwsConfig::new().await,
            database: DatabaseConfig::new()?, // Handle the Result properly
        })
    }
}
