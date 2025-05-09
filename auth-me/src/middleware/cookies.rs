use tower_cookies::{ CookieManagerLayer, Cookies, Cookie };
use time::Duration as TimeDuration;

/// Expose cookie middleware layer
pub fn cookie_layer() -> CookieManagerLayer {
    CookieManagerLayer::new()
}

pub fn get_refresh_token(cookies: &Cookies) -> Option<String> {
    cookies.get("refresh_token").map(|c| c.value().to_string())
}

pub fn remove_auth_cookies(cookies: &mut Cookies) {
    // Remove access token cookie by creating a new cookie with the same name and setting it to expire immediately
    let mut access_cookie = Cookie::new("access_token", "");
    access_cookie.set_path("/api");
    access_cookie.set_max_age(TimeDuration::new(0, 0));
    access_cookie.set_http_only(true);
    cookies.add(access_cookie);

    // Remove refresh token cookie by creating a new cookie with the same name and setting it to expire immediately
    let mut refresh_cookie = Cookie::new("refresh_token", "");
    refresh_cookie.set_path("/api/auth/refresh");
    refresh_cookie.set_max_age(TimeDuration::new(0, 0));
    refresh_cookie.set_http_only(true);
    cookies.add(refresh_cookie);
}
