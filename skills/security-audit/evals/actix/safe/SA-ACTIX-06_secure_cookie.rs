use actix_web::{
    cookie::{Cookie, SameSite},
    HttpResponse, Responder,
};

// POST /login
// Secure + HttpOnly + SameSite keeps the session cookie off plaintext HTTP.
pub async fn login() -> impl Responder {
    let token = issue_session_token();
    let cookie = Cookie::build("session_id", token)
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .finish();

    HttpResponse::Ok().cookie(cookie).body("logged in")
}

fn issue_session_token() -> String {
    // Token generation lives in the auth service
    "opaque-session-token".to_string()
}
