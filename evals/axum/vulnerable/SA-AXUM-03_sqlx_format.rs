use axum::extract::{Path, State};
use axum::http::StatusCode;
use sqlx::PgPool;

// GET /orders/{customer}
// A customer of "acme' OR '1'='1" returns every order in the table.
pub async fn list_orders(
    State(pool): State<PgPool>,
    Path(customer): Path<String>,
) -> Result<String, StatusCode> {
    let rows = sqlx::query(&format!(
        "SELECT id, total FROM orders WHERE customer = '{}'",
        customer
    ))
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(rows.len().to_string())
}
