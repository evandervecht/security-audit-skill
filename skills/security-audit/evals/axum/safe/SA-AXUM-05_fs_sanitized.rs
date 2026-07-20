use axum::extract::Path as UrlPath;
use axum::http::StatusCode;
use std::path::{Component, Path, PathBuf};

const REPORT_ROOT: &str = "./reports";

// GET /reports/{name}
// Only a single normal path component is accepted, then joined under the root.
pub async fn read_report(UrlPath(name): UrlPath<String>) -> Result<String, StatusCode> {
    let candidate = Path::new(&name);
    let mut components = candidate.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => {}
        _ => return Err(StatusCode::BAD_REQUEST),
    }

    let full: PathBuf = Path::new(REPORT_ROOT).join(candidate);
    let contents = tokio::fs::read_to_string(&full)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(contents)
}

// Fixed config path: the interpolated value is a compile-time root constant,
// and the file name is hardcoded rather than request-derived.
pub async fn load_allowlist() -> Result<String, StatusCode> {
    tokio::fs::read_to_string(format!("{}/allowlist.txt", REPORT_ROOT))
        .await
        .map_err(|_| StatusCode::NOT_FOUND)
}
