use axum::{
    middleware::Next,
    response::{ Response, IntoResponse, Html, Json },
    http::{ Request, StatusCode, HeaderValue, Method },
    body::Body,
    extract::Extension,
};
use serde_json::json;
use ring::rand::{ SystemRandom, SecureRandom };
use base64::{ Engine as _, engine::general_purpose::URL_SAFE };
use time::{ Duration, OffsetDateTime };
use serde::{ Serialize, Deserialize };
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

/// Helper function to check if a method is unsafe (requires CSRF protection)
fn is_unsafe_method(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::DELETE | Method::PATCH)
}

/// Generate a new CSRF token
fn generate_secure_token() -> String {
    let mut key_bytes: [u8; 32] = [0u8; 32];
    let system_random: SystemRandom = SystemRandom::new();
    system_random.fill(&mut key_bytes).expect("Failed to generate random bytes");
    URL_SAFE.encode(key_bytes)
}

// For making csrf tokens expirable
#[derive(Serialize, Deserialize)]
pub struct TokenData {
    token: String,
    expires_at: OffsetDateTime,
}

impl TokenData {
    fn new() -> Self {
        Self {
            token: generate_secure_token(),
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(30),
        }
    }

    fn is_valid(&self) -> bool {
        OffsetDateTime::now_utc() < self.expires_at
    }
}

#[derive(Clone)]
// Our token storage
pub struct TokenStore {
    tokens: Arc<RwLock<HashMap<String, TokenData>>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn generate_token(&self) -> String {
        let token_data = TokenData::new();
        let token = token_data.token.clone();
        self.store_token(token_data).await;
        token
    }

    pub async fn store_token(&self, token_data: TokenData) {
        let mut tokens: tokio::sync::RwLockWriteGuard<
            '_,
            HashMap<String, TokenData>
        > = self.tokens.write().await;
        tokens.insert(token_data.token.clone(), token_data);
        // Clean up expired tokens
        tokens.retain(|_, data: &mut TokenData| data.is_valid());
    }

    pub async fn validate_token(&self, token: &str) -> bool {
        let tokens: tokio::sync::RwLockReadGuard<
            '_,
            HashMap<String, TokenData>
        > = self.tokens.read().await;
        tokens
            .get(token)
            .map(|data: &TokenData| data.is_valid())
            .unwrap_or(false)
    }

    // Added cleanup method
    pub async fn cleanup_expired(&self) {
        let mut tokens: tokio::sync::RwLockWriteGuard<
            '_,
            HashMap<String, TokenData>
        > = self.tokens.write().await;
        tokens.retain(|_, data: &mut TokenData| data.is_valid());
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn csrf_middleware(
    Extension(token_store): Extension<Arc<TokenStore>>, // Changed to Extension
    request: Request<Body>,
    next: Next
) -> Result<Response, StatusCode> {
    if is_unsafe_method(request.method()) {
        let token: &str = request
            .headers()
            .get("X-CSRF-Token")
            .and_then(|t: &HeaderValue| t.to_str().ok())
            .ok_or(StatusCode::FORBIDDEN)?;

        if !token_store.validate_token(token).await {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let mut response: axum::http::Response<Body> = next.run(request).await;

    // Generate and store new token
    let token_data: TokenData = TokenData::new();
    let new_token: String = token_data.token.clone();

    token_store.store_token(token_data).await;

    if let Ok(header_value) = HeaderValue::from_str(&new_token) {
        response.headers_mut().insert("X-CSRF-Token", header_value);
    }

    Ok(response)
}

// Test endpoints
pub async fn test_csrf_get() -> impl IntoResponse {
    let html: Html<&str> = Html(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSRF Test</title>
            <meta name="csrf-token" id="csrf-token" content="">
        </head>
        <body>
            <div id="result"></div>
            <button id="showToken">Show CSRF Token</button>
            <button id="testPost">Test POST with CSRF</button>

            <script>
                // Function to update the CSRF token
                function updateCSRFToken(token) {
                    document.getElementById('csrf-token').content = token;
                }

                // Get initial CSRF token from headers
                updateCSRFToken(document.querySelector('meta[name="csrf-token"]')?.getAttribute('content'));

                document.getElementById('showToken').addEventListener('click', async () => {
                    const response = await fetch('/test-csrf-debug');
                    const data = await response.json();
                    // Update token from response header
                    const newToken = response.headers.get('X-CSRF-Token');
                    if (newToken) {
                        updateCSRFToken(newToken);
                    }
                    document.getElementById('result').textContent =
                        JSON.stringify(data, null, 2);
                });

                document.getElementById('testPost').addEventListener('click', async () => {
                    const token = document.getElementById('csrf-token').content;
                    try {
                        const response = await fetch('/test-csrf-post', {
                            method: 'POST',
                            headers: {
                                'X-CSRF-Token': token,
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ test: 'data' })
                        });
                        const result = await response.json();
                        // Update token from response header
                        const newToken = response.headers.get('X-CSRF-Token');
                        if (newToken) {
                            updateCSRFToken(newToken);
                        }
                        document.getElementById('result').textContent =
                            JSON.stringify(result, null, 2);
                    } catch (err) {
                        document.getElementById('result').textContent =
                            'Error: ' + err.message;
                    }
                });
            </script>
        </body>
        </html>
    "#
    );

    html
}

pub async fn test_csrf_post() -> impl IntoResponse {
    Json(json!({ "message": "POST successful" }))
}

pub async fn debug_csrf(request: Request<Body>) -> impl IntoResponse {
    let headers: &axum::http::HeaderMap = request.headers();
    let csrf_header: &str = headers
        .get("X-CSRF-Token")
        .and_then(|v: &HeaderValue| v.to_str().ok())
        .unwrap_or("No CSRF header");

    Json(
        json!({
        "csrf_header": csrf_header,
        "method": request.method().as_str(),
    })
    )
}

pub async fn get_csrf_token(Extension(
    token_store,
): Extension<Arc<TokenStore>>) -> impl IntoResponse {
    let token = token_store.generate_token().await;
    let mut map = HashMap::new();
    map.insert("csrf_token".to_string(), token);
    Json(map)
}
