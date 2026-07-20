use actix_web::{web, HttpResponse, Responder};
use sqlx::PgPool;

// GET /users/{email}
// An email of "x' OR '1'='1" returns every row in the table.
pub async fn find_user(pool: web::Data<PgPool>, email: web::Path<String>) -> impl Responder {
    let rows = sqlx::query(&format!(
        "SELECT id, email, role FROM users WHERE email = '{}'",
        email
    ))
    .fetch_all(pool.get_ref())
    .await;

    match rows {
        Ok(found) => HttpResponse::Ok().body(found.len().to_string()),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
