// use axum::{ http::{ HeaderValue, Request }, response::Response, middleware::Next, body::Body };

// pub async fn security_headers(request: Request<Body>, next: Next) -> Response {
//     let mut response: axum::http::Response<Body> = next.run(request).await;

//     let headers: &mut axum::http::HeaderMap = response.headers_mut();

//     headers.insert("X-DNS-Prefetch-Control", HeaderValue::from_static("off"));
//     headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
//     headers.insert(
//         "Strict-Transport-Security",
//         HeaderValue::from_static("max-age=15552000; includeSubDomains")
//     );
//     headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
//     headers.insert("X-Permitted-Cross-Domain-Policies", HeaderValue::from_static("none"));
//     headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
//     headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
//     headers.insert(
//         "Permissions-Policy",
//         HeaderValue::from_static(
//             "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
//         )
//     );

//     let environment: String = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".into());

//     let csp: &str = if environment == "production" {
//         // 🚨 Strict CSP - disallows inline scripts/styles, no 3rd party
//         "default-src 'self'; \
//          script-src 'self'; \
//          style-src 'self'; \
//          img-src 'self' data:; \
//          font-src 'self'; \
//          object-src 'none'; \
//          frame-ancestors 'none'; \
//          base-uri 'self'; \
//          form-action 'self'; \
//          upgrade-insecure-requests"
//     } else {
//         // ⚠️ Relaxed CSP for development tools
//         "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; \
//          script-src * data: blob: 'unsafe-inline' 'unsafe-eval'; \
//          style-src * data: blob: 'unsafe-inline'; \
//          img-src * data: blob:; \
//          font-src * data:; \
//          connect-src *; \
//          frame-ancestors *"
//     };

//     headers.insert("Content-Security-Policy", HeaderValue::from_str(csp).unwrap());

//     response
// }

use axum::{
    middleware::Next,
    response::Response,
    http::{ Request, HeaderValue, header, HeaderName },
    body::Body,
};

pub async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Content Security Policy
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; \
             connect-src 'self' http://localhost:8080; \
             script-src 'self' 'unsafe-inline' 'unsafe-eval';"
        )
    );

    // XSS Protection
    headers.insert(header::X_XSS_PROTECTION, HeaderValue::from_static("1; mode=block"));

    // X-Frame-Options
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    // X-Content-Type-Options
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));

    // Referrer Policy
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin")
    );

    // Strict-Transport-Security (HSTS)
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains")
    );

    // Permissions Policy
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        )
    );

    response
}
