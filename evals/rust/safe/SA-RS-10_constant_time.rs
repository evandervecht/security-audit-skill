// SA-RS-10: Constant-time comparison prevents timing side-channel
use constant_time_eq::constant_time_eq;

fn verify_auth(provided: &[u8], expected: &[u8]) -> bool {
    constant_time_eq(provided, expected)
}
