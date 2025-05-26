use redis::{ Client, Connection };
use super::ConfigError;

#[derive(Clone, Debug)]
pub struct CacheConfig {
    client: Client,
}

impl CacheConfig {
    pub fn new(redis_url: &str) -> Result<Self, ConfigError> {
        let client = Client::open(redis_url)?;
        Ok(Self { client })
    }

    pub async fn get_connection(&self) -> Result<Connection, ConfigError> {
        Ok(self.client.get_connection()?)
    }
}
