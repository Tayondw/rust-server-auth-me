use tower_cookies::{CookieManagerLayer, Cookies, Cookie};
use axum::{response::IntoResponse, Json};
use serde_json::json;

/// Adds a signed cookie
pub fn set_jwt_cookie(cookies: &Cookies, token: &str) {
    let mut cookie = Cookie::new("jwt", token.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(true);

    cookies.add(cookie);
}

/// Retrieves JWT from cookie
pub fn get_jwt_cookie(cookies: &Cookies) -> Option<String> {
    cookies.get("jwt").map(|c| c.value().to_string())
}

/// Example protected route using the jwt cookie
pub async fn protected_route(cookies: Cookies) -> impl IntoResponse {
    match get_jwt_cookie(&cookies) {
        Some(token) => Json(json!({
            "success": true,
            "token": token
        }))
        .into_response(),

        None => Json(json!({
            "success": false,
            "message": "Unauthorized"
        }))
        .into_response(),
    }
}

/// Expose cookie middleware layer
pub fn cookie_layer() -> CookieManagerLayer {
    CookieManagerLayer::new()
}

// Test route to set JWT cookie
pub async fn test_set_jwt(cookies: Cookies) -> impl IntoResponse {
    // Create a sample JWT token - in production this would be properly generated
    let test_token = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    
    // Set the JWT cookie
    set_jwt_cookie(&cookies, test_token);
    
    // Return a response we can see in the browser
    Json(json!({
        "message": "JWT cookie is set",
        "status": "success",
        "test_token": test_token
    }))
}

// Test route to verify JWT cookie
pub async fn test_get_jwt(cookies: Cookies) -> impl IntoResponse {
    match get_jwt_cookie(&cookies) {
        Some(token) => Json(json!({
            "message": "JWT cookie found",
            "token": token
        })),
        None => Json(json!({
            "message": "No JWT cookie found",
            "token": null
        }))
    }
}