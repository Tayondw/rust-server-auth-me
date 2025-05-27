use axum::{
    extract::{ ConnectInfo, Request },
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{ Arc, Mutex };
use std::time::{ Duration, Instant };
use tracing::warn;

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: u32,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_minutes: u64) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_duration: Duration::from_secs(window_minutes * 60),
        }
    }

    pub async fn middleware(
        &self,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        request: Request,
        next: Next
    ) -> Result<Response, StatusCode> {
        let client_ip = addr.ip().to_string();

        if self.is_rate_limited(&client_ip) {
            warn!("Rate limit exceeded for IP: {}", client_ip);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        self.record_request(&client_ip);
        Ok(next.run(request).await)
    }

    fn is_rate_limited(&self, client_ip: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();

        let client_requests = requests.entry(client_ip.to_string()).or_insert_with(Vec::new);

        // Remove old requests outside the window
        client_requests.retain(|&timestamp| now.duration_since(timestamp) < self.window_duration);

        client_requests.len() >= (self.max_requests as usize)
    }

    fn record_request(&self, client_ip: &str) {
        let mut requests = self.requests.lock().unwrap();
        let client_requests = requests.entry(client_ip.to_string()).or_insert_with(Vec::new);
        client_requests.push(Instant::now());
    }
}
