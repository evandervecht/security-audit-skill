// SA-RS-07: Shell invocation with user input enables command injection
use std::process::Command;

fn process_file(filename: &str) -> std::io::Result<Vec<u8>> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("cat {}", filename))
        .output()?;
    Ok(output.stdout)
}
