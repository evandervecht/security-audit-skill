// SA-RS-01: Safe bounds-checked access using Option
fn get_item(data: &[u8], index: usize) -> Option<u8> {
    data.get(index).copied()
}
