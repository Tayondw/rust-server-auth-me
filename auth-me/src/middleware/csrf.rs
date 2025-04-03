use axum::{
    middleware::Next,
    response::Response,
    http::{Request, StatusCode, HeaderValue, header},
};
use csrf::{AesGcmCsrfProtection, CsrfProtection};

pub async fn csrf_middleware<B>(
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let csrf_protection = AesGcmCsrfProtection::new();
    let token = csrf_protection.generate_token();

    // Only verify POST/PUT/DELETE/PATCH requests
    if request.method().is_unsafe() {
        // Get token from request header
        let request_token = request
            .headers()
            .get("X-CSRF-Token")
            .and_then(|t| t.to_str().ok())
            .ok_or(StatusCode::FORBIDDEN)?;

        // Verify the token
        csrf_protection
            .verify_token(request_token)
            .map_err(|_| StatusCode::FORBIDDEN)?;
    }

    // Process the request
    let mut response = next.run(request).await;

    // Add new token to response headers
    response.headers_mut().insert(
        "X-CSRF-Token",
        HeaderValue::from_str(&token).unwrap(),
    );

    Ok(response)
}