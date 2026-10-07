use axum::extract::Query;
use axum::response::Html;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Greeting {
    name: String,
}

// GET /greet?name=<script>...</script>
// The query value is interpolated into markup without any escaping.
pub async fn greet(Query(params): Query<Greeting>) -> Html<String> {
    Html(format!("<h1>Welcome back, {}!</h1>", params.name))
}
