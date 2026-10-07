use actix_web::{http::header::ContentType, web, HttpResponse, Responder};

#[derive(serde::Deserialize)]
pub struct SearchQuery {
    q: String,
}

// GET /search?q=<script>...</script>
// The query string value lands unescaped inside the HTML body.
pub async fn search(query: web::Query<SearchQuery>) -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(format!("<h1>Results for {}</h1><p>No matches.</p>", query.q))
}
