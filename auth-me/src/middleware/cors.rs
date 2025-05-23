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
            .allow_origin("http://localhost:5173".parse::<HeaderValue>().unwrap())
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
                HeaderName::from_static("x-csrf-token"), 
            ])

            .allow_credentials(true)
    }
}
