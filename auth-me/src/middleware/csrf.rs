use axum::{
    middleware::Next,
    response::Response,
    http::{Request, StatusCode, HeaderValue, Method},
    body::Body,
};

/// CSRF middleware for protecting against Cross-Site Request Forgery attacks
pub async fn csrf_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Only verify CSRF token for unsafe methods
    if is_unsafe_method(request.method()) {
        // Check for CSRF token in headers
        let token = request
            .headers()
            .get("X-CSRF-Token")
            .and_then(|t| t.to_str().ok())
            .ok_or(StatusCode::FORBIDDEN)?;

        // In a real implementation, verify the token against a stored value
        if token.is_empty() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Process the request
    let mut response = next.run(request).await;

    // Generate and add new CSRF token to response
    let new_token = generate_token();
    if let Ok(header_value) = HeaderValue::from_str(&new_token) {
        response.headers_mut().insert("X-CSRF-Token", header_value);
    }

    Ok(response)
}

/// Helper function to check if a method is unsafe (requires CSRF protection)
fn is_unsafe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}

/// Generate a new CSRF token
fn generate_token() -> String {
    use rand::{rng, Rng};
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    const TOKEN_LEN: usize = 32;

    let mut rng = rng();

    let token: String = (0..TOKEN_LEN)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    token
}