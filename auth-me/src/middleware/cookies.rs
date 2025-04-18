use tower_cookies::{ CookieManagerLayer, Cookies, Cookie };
use time::Duration;
use cookie::SameSite;
use crate::config::Config;

const ACCESS_COOKIE_NAME: &'static str = "access_token";
const REFRESH_COOKIE_NAME: &'static str = "refresh_token";
const DEFAULT_ACCESS_TOKEN_EXPIRES: i64 = 900; // 15 minutes in seconds
const DEFAULT_REFRESH_TOKEN_EXPIRES: i64 = 604800; // 7 days in seconds

/// Expose cookie middleware layer
pub fn cookie_layer() -> CookieManagerLayer {
    CookieManagerLayer::new()
}

pub struct TokenCookieOptions {
    pub http_only: bool,
    pub secure: bool,
    pub same_site: SameSite,
    pub path: String,
    pub max_age: Option<Duration>,
}

impl Default for TokenCookieOptions {
    fn default() -> Self {
        Self {
            http_only: true,
            secure: true,
            same_site: SameSite::Strict,
            path: "/".to_string(),
            max_age: None,
        }
    }
}

pub fn set_token_cookie(
    cookies: &Cookies,
    name: String, // Take ownership of the name
    token: String, // Take ownership of the token
    options: TokenCookieOptions
) {
    let mut cookie = Cookie::new(name, token);
    cookie.set_http_only(options.http_only);
    cookie.set_secure(options.secure);
    cookie.set_same_site(options.same_site);
    cookie.set_path(options.path);

    if let Some(max_age) = options.max_age {
        cookie.set_max_age(max_age);
    }

    cookies.add(cookie);
}

pub fn set_access_token(cookies: &Cookies, token: String, config: &Config) {
    let expires_in = if config.database.jwt_expires_in <= 0 {
        DEFAULT_ACCESS_TOKEN_EXPIRES
    } else {
        config.database.jwt_expires_in
    };

    let options = TokenCookieOptions {
        path: "/api".to_string(),
        max_age: Some(Duration::seconds(expires_in)),
        ..Default::default()
    };
    set_token_cookie(cookies, ACCESS_COOKIE_NAME.to_string(), token, options);
}

pub fn set_refresh_token(cookies: &Cookies, token: String, config: &Config) {
    let expires_in = if config.database.jwt_refresh_expires_in <= 0 {
        DEFAULT_REFRESH_TOKEN_EXPIRES
    } else {
        config.database.jwt_refresh_expires_in
    };

    let options = TokenCookieOptions {
        path: "/api/auth/refresh".to_string(),
        max_age: Some(Duration::seconds(expires_in)),
        ..Default::default()
    };
    set_token_cookie(cookies, REFRESH_COOKIE_NAME.to_string(), token, options);
}

pub fn get_access_token(cookies: &Cookies) -> Option<String> {
    cookies.get(ACCESS_COOKIE_NAME).map(|c| c.value().to_string())
}

pub fn get_refresh_token(cookies: &Cookies) -> Option<String> {
    cookies.get(REFRESH_COOKIE_NAME).map(|c| c.value().to_string())
}

pub fn remove_auth_cookies(cookies: &Cookies) {
    let mut access_cookie = Cookie::new(ACCESS_COOKIE_NAME, "");
    access_cookie.set_path("/api");
    access_cookie.set_max_age(Duration::seconds(0));

    let mut refresh_cookie = Cookie::new(REFRESH_COOKIE_NAME, "");
    refresh_cookie.set_path("/api/auth/refresh");
    refresh_cookie.set_max_age(Duration::seconds(0));

    cookies.add(access_cookie);
    cookies.add(refresh_cookie);
}
