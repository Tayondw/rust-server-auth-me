use axum::http::{ HeaderName, HeaderValue, Method };
use tower_http::cors::CorsLayer;

pub fn create_cors_layer(environment: &str) -> CorsLayer {
    if environment == "production" {
        CorsLayer::new()
            .allow_origin("https://your-production-domain.com".parse::<HeaderValue>().unwrap())
            .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
            .allow_headers([
                HeaderName::from_static("content-type"),
                HeaderName::from_static("authorization"),
            ])
            .allow_credentials(true)
    } else {
        CorsLayer::new()
            .allow_origin("http://127.0.0.1:8080".parse::<HeaderValue>().unwrap())
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                HeaderName::from_static("content-type"),
                HeaderName::from_static("authorization"),
                HeaderName::from_static("accept"),
            ])
            .allow_credentials(true)
    }
}
