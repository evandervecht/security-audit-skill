use actix_cors::Cors;
use actix_web::{web, App, HttpServer};

mod routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Wide-open CORS left over from local development
        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
            .route("/api/orders", web::get().to(routes::list_orders))
            .route("/api/orders", web::post().to(routes::create_order))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
