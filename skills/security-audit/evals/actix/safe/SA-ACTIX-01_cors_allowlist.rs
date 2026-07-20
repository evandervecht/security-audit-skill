use actix_cors::Cors;
use actix_web::{http::header, web, App, HttpServer};

mod routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Explicit origin allowlist for the production frontend
        let cors = Cors::default()
            .allowed_origin("https://app.example.com")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(3600);

        App::new()
            .wrap(cors)
            .route("/api/orders", web::get().to(routes::list_orders))
            .route("/api/orders", web::post().to(routes::create_order))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
