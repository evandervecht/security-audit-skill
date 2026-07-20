use axum::extract::{Path, State};
use axum::http::StatusCode;
use sqlx::PgPool;

// GET /orders/{customer}
// The customer value travels as a bind parameter; the driver quotes it.
pub async fn list_orders(
    State(pool): State<PgPool>,
    Path(customer): Path<String>,
) -> Result<String, StatusCode> {
    let rows = sqlx::query("SELECT id, total FROM orders WHERE customer = $1")
        .bind(&customer)
        .fetch_all(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(rows.len().to_string())
}
