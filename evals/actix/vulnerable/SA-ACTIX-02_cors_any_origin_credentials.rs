use actix_cors::Cors;
use actix_web::{web, App, HttpServer};

mod handlers;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Reflects every Origin header AND allows cookies to ride along
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .supports_credentials();

        App::new()
            .wrap(cors)
            .route("/api/profile", web::get().to(handlers::profile))
            .route("/api/profile", web::put().to(handlers::update_profile))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
