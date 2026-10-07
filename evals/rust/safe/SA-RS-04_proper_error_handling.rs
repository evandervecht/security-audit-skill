// SA-RS-04: Proper error handling with Result and ? operator
fn handle_request(body: &str) -> Result<Response, AppError> {
    let data: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| AppError::BadRequest("invalid JSON"))?;
    let name = data["name"].as_str()
        .ok_or(AppError::BadRequest("missing name"))?;
    Ok(Response::ok(name))
}
