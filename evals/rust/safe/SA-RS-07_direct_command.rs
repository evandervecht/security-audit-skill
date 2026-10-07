// SA-RS-07: Direct command execution without shell wrapper
use std::process::Command;

fn process_file(filename: &str) -> std::io::Result<Vec<u8>> {
    let output = Command::new("cat")
        .arg(filename)
        .output()?;
    Ok(output.stdout)
}
