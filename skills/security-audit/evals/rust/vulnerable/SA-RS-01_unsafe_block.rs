// SA-RS-01: Unsafe block with raw pointer dereference
fn read_raw(ptr: *const u8) -> u8 {
    unsafe {
        *ptr
    }
}
