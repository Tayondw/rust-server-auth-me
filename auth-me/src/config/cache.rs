use redis::{ Client, Connection };
use std::time::Duration;

#[derive(Clone)]
pub struct CacheConfig {
    client: Client,
}

impl CacheConfig {
    pub fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = Client::open(redis_url)?;
        Ok(Self { client })
    }

    pub async fn get_connection(&self) -> Result<Connection, redis::RedisError> {
        self.client.get_connection()
    }
}
