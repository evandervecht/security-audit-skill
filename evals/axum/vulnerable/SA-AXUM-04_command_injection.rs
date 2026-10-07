use axum::extract::Query;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct PingParams {
    host: String,
}

// GET /ping?host=8.8.8.8;cat+/etc/passwd
// The query value is spliced into a shell command line.
pub async fn ping(Query(params): Query<PingParams>) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 1 {}", params.host))
        .output();

    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
        Err(err) => format!("ping failed: {}", err),
    }
}
