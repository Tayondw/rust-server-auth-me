use axum::{
    http::{ HeaderValue, Request, header, HeaderName },
    response::Response,
    middleware::Next,
    body::Body,
};

pub async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response: axum::http::Response<Body> = next.run(request).await;

    let headers: &mut header::HeaderMap = response.headers_mut();

    // X-DNS-Prefetch-Control
    headers.insert(header::X_DNS_PREFETCH_CONTROL, HeaderValue::from_static("off"));

    // X-Frame-Options
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    // Strict-Transport-Security (HSTS)
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains")
    );

    // X-Content-Type-Options
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));

    headers.insert("X-Permitted-Cross-Domain-Policies", HeaderValue::from_static("none"));

    // Referrer Policy
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin")
    );

    // XSS Protection
    headers.insert(header::X_XSS_PROTECTION, HeaderValue::from_static("1; mode=block"));

    // Permissions Policy
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        )
    );

    let environment: String = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".into());

    // Content Security Policy
    let csp: &str = if environment == "production" {
        // 🚨 Strict CSP - disallows inline scripts/styles, no 3rd party
        "default-src 'self'; \
         script-src 'self'; \
         style-src 'self'; \
         img-src 'self' data:; \
         font-src 'self'; \
         object-src 'none'; \
         frame-ancestors 'none'; \
         base-uri 'self'; \
         form-action 'self'; \
         upgrade-insecure-requests"
    } else {
        // ⚠️ Relaxed CSP for development tools
        "default-src 'self'; \
         script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
         style-src * data: blob: 'unsafe-inline'; \
         img-src * data: blob:; \
         font-src * data:; \
          connect-src 'self' http://localhost:8080; \
         frame-ancestors *"
    };

    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(csp).unwrap());

    response
}