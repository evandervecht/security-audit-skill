use askama::Template;
use axum::extract::Query;
use axum::response::{Html, IntoResponse};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "greeting.html")]
struct GreetingTemplate {
    name: String,
}

#[derive(Deserialize)]
pub struct Greeting {
    name: String,
}

// GET /greet?name=...
// Askama HTML-escapes the name before it reaches the response body.
pub async fn greet(Query(params): Query<Greeting>) -> impl IntoResponse {
    let page = GreetingTemplate { name: params.name };
    match page.render() {
        Ok(body) => Html(body).into_response(),
        Err(_) => "template error".into_response(),
    }
}

// Newtype for pages that were already rendered (and escaped) by askama.
pub struct PrerenderedHtml(pub String);

// The interpolated value here is template output, already escaped above.
pub fn cache_entry(body: String) -> PrerenderedHtml {
    PrerenderedHtml(format!("<!-- cached -->{}", body))
}
