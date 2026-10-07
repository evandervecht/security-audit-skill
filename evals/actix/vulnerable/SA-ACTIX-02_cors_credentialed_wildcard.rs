use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer};

async fn account_balance() -> HttpResponse {
    // Session cookie authenticates this endpoint.
    HttpResponse::Ok().json(serde_json::json!({ "balance": 1024.50 }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Any origin may send the session cookie and read the response.
        let cors = Cors::default().allow_any_origin().supports_credentials();
        App::new()
            .wrap(cors)
            .route("/api/balance", web::get().to(account_balance))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
