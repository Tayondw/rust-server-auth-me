// Application metrics and monitoring middleware

use axum::{ extract::{ Request, MatchedPath }, response::Response, middleware::Next };
use std::{
    collections::HashMap,
    sync::{ Arc, Mutex },
    time::{ Duration, Instant, SystemTime, UNIX_EPOCH },
};
use serde::{ Serialize, Deserialize };
use tracing::{ info, warn };

/// Application metrics collector
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    metrics: Arc<Mutex<ApplicationMetrics>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationMetrics {
    pub request_count: HashMap<String, u64>,
    pub response_times: HashMap<String, Vec<u64>>, // Response times in milliseconds
    pub status_codes: HashMap<u16, u64>,
    pub error_count: u64,
    pub uptime_start: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub database_queries: u64,
    pub email_sent: u64,
    pub email_failed: u64,
    pub active_sessions: u64,
    pub failed_login_attempts: u64,
    pub successful_logins: u64,
}

impl Default for ApplicationMetrics {
    fn default() -> Self {
        Self {
            request_count: HashMap::new(),
            response_times: HashMap::new(),
            status_codes: HashMap::new(),
            error_count: 0,
            uptime_start: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            cache_hits: 0,
            cache_misses: 0,
            database_queries: 0,
            email_sent: 0,
            email_failed: 0,
            active_sessions: 0,
            failed_login_attempts: 0,
            successful_logins: 0,
        }
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(ApplicationMetrics::default())),
        }
    }

    /// Record a request
    pub fn record_request(&self, path: &str, status_code: u16, duration: Duration) {
        let mut metrics = self.metrics.lock().unwrap();

        // Count requests by path
        *metrics.request_count.entry(path.to_string()).or_insert(0) += 1;

        // Record response time
        let duration_ms = duration.as_millis() as u64;
        metrics.response_times.entry(path.to_string()).or_insert_with(Vec::new).push(duration_ms);

        // Keep only last 100 response times per endpoint
        if let Some(times) = metrics.response_times.get_mut(path) {
            if times.len() > 100 {
                times.drain(0..times.len() - 100);
            }
        }

        // Count status codes
        *metrics.status_codes.entry(status_code).or_insert(0) += 1;

        // Count errors
        if status_code >= 500 {
            metrics.error_count += 1;
            warn!("Server error on {}: {}", path, status_code);
        }
    }

    /// Record cache hit
    pub fn record_cache_hit(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.cache_hits += 1;
    }

    /// Record cache miss
    pub fn record_cache_miss(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.cache_misses += 1;
    }

    /// Record database query
    pub fn record_database_query(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.database_queries += 1;
    }

    /// Record successful email
    pub fn record_email_sent(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.email_sent += 1;
    }

    /// Record failed email
    pub fn record_email_failed(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.email_failed += 1;
    }

    /// Record successful login
    pub fn record_successful_login(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.successful_logins += 1;
    }

    /// Record failed login attempt
    pub fn record_failed_login(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.failed_login_attempts += 1;
    }

    /// Update active sessions count
    pub fn set_active_sessions(&self, count: u64) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.active_sessions = count;
    }

    /// Get current metrics snapshot
    pub fn get_metrics(&self) -> ApplicationMetrics {
        let metrics = self.metrics.lock().unwrap();
        metrics.clone()
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> MetricsSummary {
        let metrics = self.metrics.lock().unwrap();

        let total_requests: u64 = metrics.request_count.values().sum();
        let error_rate = if total_requests > 0 {
            ((metrics.error_count as f64) / (total_requests as f64)) * 100.0
        } else {
            0.0
        };

        let cache_hit_rate = if metrics.cache_hits + metrics.cache_misses > 0 {
            ((metrics.cache_hits as f64) / ((metrics.cache_hits + metrics.cache_misses) as f64)) *
                100.0
        } else {
            0.0
        };

        let email_success_rate = if metrics.email_sent + metrics.email_failed > 0 {
            ((metrics.email_sent as f64) / ((metrics.email_sent + metrics.email_failed) as f64)) *
                100.0
        } else {
            100.0
        };

        let uptime_seconds =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - metrics.uptime_start;

        // Calculate average response times
        let mut avg_response_times = HashMap::new();
        for (path, times) in &metrics.response_times {
            if !times.is_empty() {
                let avg = times.iter().sum::<u64>() / (times.len() as u64);
                avg_response_times.insert(path.clone(), avg);
            }
        }

        MetricsSummary {
            total_requests,
            error_rate,
            cache_hit_rate,
            email_success_rate,
            uptime_seconds,
            most_accessed_endpoints: Self::get_top_endpoints(&metrics.request_count, 5),
            slowest_endpoints: Self::get_slowest_endpoints(&avg_response_times, 5),
            avg_response_times,
        }
    }

    fn get_top_endpoints(request_count: &HashMap<String, u64>, limit: usize) -> Vec<(String, u64)> {
        let mut endpoints: Vec<_> = request_count.iter().collect();
        endpoints.sort_by(|a, b| b.1.cmp(a.1));
        endpoints
            .into_iter()
            .take(limit)
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    fn get_slowest_endpoints(avg_times: &HashMap<String, u64>, limit: usize) -> Vec<(String, u64)> {
        let mut endpoints: Vec<_> = avg_times.iter().collect();
        endpoints.sort_by(|a, b| b.1.cmp(a.1));
        endpoints
            .into_iter()
            .take(limit)
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Reset metrics (useful for testing or periodic resets)
    pub fn reset(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        *metrics = ApplicationMetrics::default();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub total_requests: u64,
    pub error_rate: f64,
    pub cache_hit_rate: f64,
    pub email_success_rate: f64,
    pub uptime_seconds: u64,
    pub avg_response_times: HashMap<String, u64>,
    pub most_accessed_endpoints: Vec<(String, u64)>,
    pub slowest_endpoints: Vec<(String, u64)>,
}

/// Metrics middleware for tracking request performance
pub async fn metrics_middleware(request: Request, next: Next) -> Response {
    let start_time = Instant::now();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("unknown")
        .to_string();

    let response = next.run(request).await;
    let duration = start_time.elapsed();
    let status_code = response.status().as_u16();

    // Extract metrics collector from request extensions if available
    // In practice, you'd inject this into the app state
    info!("Request {} completed in {}ms with status {}", path, duration.as_millis(), status_code);

    response
}

/// Health check endpoint data
#[derive(Debug, Serialize)]
pub struct HealthCheck {
    pub status: String,
    pub timestamp: u64,
    pub uptime_seconds: u64,
    pub version: String,
    pub environment: String,
    pub database_status: String,
    pub redis_status: String,
    pub email_status: String,
}

impl HealthCheck {
    pub fn new() -> Self {
        Self {
            status: "healthy".to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            uptime_seconds: 0, // This would be calculated based on app start time
            version: env!("CARGO_PKG_VERSION").to_string(),
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "unknown".to_string()),
            database_status: "unknown".to_string(),
            redis_status: "unknown".to_string(),
            email_status: "unknown".to_string(),
        }
    }

    pub async fn check_database_health(
        &mut self,
        pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::PgConnection>>
    ) {
        match pool.get() {
            Ok(mut conn) => {
                // Try a simple query
                use diesel::prelude::*;
                match diesel::sql_query("SELECT 1").execute(&mut conn) {
                    Ok(_) => {
                        self.database_status = "healthy".to_string();
                    }
                    Err(_) => {
                        self.database_status = "unhealthy".to_string();
                    }
                }
            }
            Err(_) => {
                self.database_status = "connection_failed".to_string();
            }
        }
    }

    pub async fn check_redis_health(&mut self, redis_url: &str) {
        match redis::Client::open(redis_url) {
            Ok(client) => {
                match client.get_connection() {
                    Ok(mut conn) => {
                        use redis::Commands;
                        match conn.ping::<String>() {
                            Ok(_) => {
                                self.redis_status = "healthy".to_string();
                            }
                            Err(_) => {
                                self.redis_status = "ping_failed".to_string();
                            }
                        }
                    }
                    Err(_) => {
                        self.redis_status = "connection_failed".to_string();
                    }
                }
            }
            Err(_) => {
                self.redis_status = "client_error".to_string();
            }
        }
    }

    pub fn check_email_health(&mut self) {
        // In a real implementation, you might try to connect to SMTP server
        // For now, just check if configuration is present
        match std::env::var("SMTP_SERVER") {
            Ok(_) => {
                self.email_status = "configured".to_string();
            }
            Err(_) => {
                self.email_status = "not_configured".to_string();
            }
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.status == "healthy" &&
            self.database_status == "healthy" &&
            (self.redis_status == "healthy" || self.redis_status == "configured") &&
            (self.email_status == "configured" || self.email_status == "healthy")
    }
}

/// Performance monitoring for database queries
pub struct DatabaseMetrics {
    query_count: Arc<Mutex<u64>>,
    slow_query_threshold_ms: u64,
    slow_queries: Arc<Mutex<Vec<SlowQuery>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlowQuery {
    pub query: String,
    pub duration_ms: u64,
    pub timestamp: u64,
}

impl DatabaseMetrics {
    pub fn new(slow_query_threshold_ms: u64) -> Self {
        Self {
            query_count: Arc::new(Mutex::new(0)),
            slow_query_threshold_ms,
            slow_queries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn record_query(&self, query: &str, duration: Duration) {
        {
            let mut count = self.query_count.lock().unwrap();
            *count += 1;
        }

        let duration_ms = duration.as_millis() as u64;
        if duration_ms > self.slow_query_threshold_ms {
            let mut slow_queries = self.slow_queries.lock().unwrap();
            slow_queries.push(SlowQuery {
                query: query.to_string(),
                duration_ms,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            });

            // ✅ Get length first, then use it
            let current_len = slow_queries.len();
            if current_len > 50 {
                slow_queries.drain(0..current_len - 50);
            }

            warn!("Slow query detected ({}ms): {}", duration_ms, query);
        }
    }

    pub fn get_query_count(&self) -> u64 {
        *self.query_count.lock().unwrap()
    }

    pub fn get_slow_queries(&self) -> Vec<SlowQuery> {
        self.slow_queries.lock().unwrap().clone()
    }
}

/// Memory usage tracking
#[derive(Debug, Serialize)]
pub struct MemoryMetrics {
    pub allocated_bytes: u64,
    pub deallocated_bytes: u64,
    pub current_usage_bytes: u64,
    pub peak_usage_bytes: u64,
}

impl MemoryMetrics {
    pub fn new() -> Self {
        Self {
            allocated_bytes: 0,
            deallocated_bytes: 0,
            current_usage_bytes: 0,
            peak_usage_bytes: 0,
        }
    }

    // In a real implementation, you'd use a memory profiler
    // or system calls to get actual memory usage
    pub fn update_from_system(&mut self) {
        // Placeholder implementation
        // In practice, you'd use something like:
        // - /proc/self/status on Linux
        // - Windows API calls
        // - macOS system calls

        self.current_usage_bytes = 0; // Would be actual value
        if self.current_usage_bytes > self.peak_usage_bytes {
            self.peak_usage_bytes = self.current_usage_bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        // Record some test metrics
        collector.record_request("/api/users", 200, Duration::from_millis(150));
        collector.record_request("/api/users", 404, Duration::from_millis(50));
        collector.record_cache_hit();
        collector.record_cache_miss();

        let metrics = collector.get_metrics();
        assert_eq!(metrics.request_count.get("/api/users"), Some(&2));
        assert_eq!(metrics.status_codes.get(&200), Some(&1));
        assert_eq!(metrics.status_codes.get(&404), Some(&1));
        assert_eq!(metrics.cache_hits, 1);
        assert_eq!(metrics.cache_misses, 1);

        let summary = collector.get_summary();
        assert_eq!(summary.total_requests, 2);
        assert_eq!(summary.cache_hit_rate, 50.0);
    }

    #[test]
    fn test_health_check() {
        let health = HealthCheck::new();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_database_metrics() {
        let db_metrics = DatabaseMetrics::new(100); // 100ms threshold

        // Record a fast query
        db_metrics.record_query("SELECT 1", Duration::from_millis(50));
        assert_eq!(db_metrics.get_query_count(), 1);
        assert_eq!(db_metrics.get_slow_queries().len(), 0);

        // Record a slow query
        db_metrics.record_query("SELECT * FROM large_table", Duration::from_millis(200));
        assert_eq!(db_metrics.get_query_count(), 2);
        assert_eq!(db_metrics.get_slow_queries().len(), 1);
    }
}
