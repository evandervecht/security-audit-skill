use axum::response::IntoResponse;
use axum_extra::extract::cookie::{Cookie, CookieJar};

// POST /login
// The session cookie may be replayed over plaintext HTTP by any browser.
pub async fn login(jar: CookieJar) -> impl IntoResponse {
    let token = issue_session_token();
    let cookie = Cookie::build(("session", token))
        .path("/")
        .http_only(true)
        .secure(false)
        .build();

    (jar.add(cookie), "logged in")
}

fn issue_session_token() -> String {
    // Token generation lives in the auth service
    "opaque-session-token".to_string()
}
