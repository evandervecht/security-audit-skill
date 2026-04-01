// SA-RS-04: unwrap in request handler can panic and crash server
fn handle_request(body: &str) -> Response {
    let data: serde_json::Value = serde_json::from_str(body).unwrap();
    let name = data["name"].as_str().unwrap();
    Response::ok(name)
}
