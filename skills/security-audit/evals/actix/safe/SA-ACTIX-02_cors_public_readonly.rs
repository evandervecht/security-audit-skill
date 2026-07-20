use actix_cors::Cors;
use actix_web::{web, App, HttpServer};

mod handlers;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Public, unauthenticated read-only API: wildcard origin is fine
        // because no cookies or auth headers are ever accepted here.
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET"])
            .max_age(86400);

        App::new()
            .wrap(cors)
            .route("/api/status", web::get().to(handlers::status))
            .route("/api/changelog", web::get().to(handlers::changelog))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
