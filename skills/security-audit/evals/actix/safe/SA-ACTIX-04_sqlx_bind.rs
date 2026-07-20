use actix_web::{web, HttpResponse, Responder};
use sqlx::PgPool;

// GET /users/{email}
// The email value travels as a bind parameter; the driver handles quoting.
pub async fn find_user(pool: web::Data<PgPool>, email: web::Path<String>) -> impl Responder {
    let rows = sqlx::query("SELECT id, email, role FROM users WHERE email = $1")
        .bind(email.as_str())
        .fetch_all(pool.get_ref())
        .await;

    match rows {
        Ok(found) => HttpResponse::Ok().body(found.len().to_string()),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
