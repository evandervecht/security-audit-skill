use actix_web::{http::header::ContentType, web, HttpResponse, Responder};
use askama::Template;

#[derive(Template)]
#[template(path = "search.html")]
struct SearchTemplate<'a> {
    query: &'a str,
}

#[derive(serde::Deserialize)]
pub struct SearchQuery {
    q: String,
}

// GET /search?q=...
// Askama escapes interpolated values by default, so markup in q is inert.
pub async fn search(query: web::Query<SearchQuery>) -> impl Responder {
    let page = SearchTemplate { query: &query.q };
    match page.render() {
        Ok(html) => HttpResponse::Ok()
            .content_type(ContentType::html())
            .body(html),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

// Plain-text responses interpolated with format! carry no HTML sink.
pub async fn uptime(seconds: web::Data<u64>) -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(format!("uptime {} seconds", seconds.get_ref()))
}

// A "<" used as a numeric comparison in plain text is not markup.
pub async fn quota(used: web::Data<u64>) -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(format!("used {} GB (expected < {} GB)", used.get_ref(), 100))
}
