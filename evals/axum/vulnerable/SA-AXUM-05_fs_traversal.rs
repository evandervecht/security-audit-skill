use axum::extract::Path;
use axum::http::StatusCode;

// GET /reports/{name}
// A name of "..%2F..%2F.env" reads files outside the reports directory.
pub async fn read_report(Path(name): Path<String>) -> Result<String, StatusCode> {
    let contents = tokio::fs::read_to_string(format!("./reports/{}", name))
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(contents)
}

// GET /exports/{id}
pub async fn read_export(Path(id): Path<String>) -> Result<Vec<u8>, StatusCode> {
    let bytes = tokio::fs::read(format!("./exports/{}.csv", id))
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(bytes)
}
