use axum::extract::Query;
use axum::http::StatusCode;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct PingParams {
    host: String,
}

fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

// GET /ping?host=example.com
// No shell involved: the validated host is a single argv entry.
pub async fn ping(Query(params): Query<PingParams>) -> Result<String, StatusCode> {
    if !is_valid_hostname(&params.host) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let output = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg(&params.host)
        .output()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[derive(Deserialize)]
pub struct ProbeParams {
    count: u32,
}

// GET /probe?count=4
// "-c" here is ping's packet-count flag; the formatted value is a bounded u32.
pub async fn probe(Query(params): Query<ProbeParams>) -> Result<String, StatusCode> {
    let count = params.count.clamp(1, 5);
    let output = Command::new("ping")
        .arg("-c").arg(format!("{}", count))
        .arg("198.51.100.1")
        .output()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
