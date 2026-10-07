use axum::response::IntoResponse;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

// POST /login
// Secure + HttpOnly + SameSite keeps the session cookie off plaintext HTTP.
pub async fn login(jar: CookieJar) -> impl IntoResponse {
    let token = issue_session_token();
    let cookie = Cookie::build(("session", token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .build();

    (jar.add(cookie), "logged in")
}

fn issue_session_token() -> String {
    // Token generation lives in the auth service
    "opaque-session-token".to_string()
}
