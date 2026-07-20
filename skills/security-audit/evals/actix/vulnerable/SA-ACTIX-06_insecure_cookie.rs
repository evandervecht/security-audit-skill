use actix_web::{cookie::Cookie, HttpResponse, Responder};

// POST /login
// The session cookie may be replayed over plaintext HTTP by any browser.
pub async fn login() -> impl Responder {
    let token = issue_session_token();
    let cookie = Cookie::build("session_id", token)
        .path("/")
        .http_only(true)
        .secure(false)
        .finish();

    HttpResponse::Ok().cookie(cookie).body("logged in")
}

fn issue_session_token() -> String {
    // Token generation lives in the auth service
    "opaque-session-token".to_string()
}
