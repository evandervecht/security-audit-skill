use axum::{routing::get, Router};
use tower_http::cors::CorsLayer;

mod handlers;

#[tokio::main]
async fn main() {
    // Mirrors every Origin header and allows credentials to ride along
    let cors = CorsLayer::very_permissive();

    let app = Router::new()
        .route("/api/me", get(handlers::me))
        .route("/api/settings", get(handlers::settings))
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
