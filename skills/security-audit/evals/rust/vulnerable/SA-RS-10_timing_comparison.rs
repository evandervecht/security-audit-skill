// SA-RS-10: Standard equality leaks timing information on secrets
fn verify_auth(provided: &str, expected_token: &str) -> bool {
    provided == token
}
