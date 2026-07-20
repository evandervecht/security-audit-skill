use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer};

async fn account_balance() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "balance": 1024.50 }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Credentials are only shared with the single pinned origin.
        let cors = Cors::default()
            .allowed_origin("https://portal.example.com")
            .supports_credentials()
            .max_age(3600);
        App::new()
            .wrap(cors)
            .route("/api/balance", web::get().to(account_balance))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
