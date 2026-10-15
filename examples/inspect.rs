//! Native CLI for the same analysis the web page runs:
//!   cargo run --example inspect -- path/to/file
fn main() {
    let path = std::env::args().nth(1).expect("usage: inspect <file>");
    let bytes = std::fs::read(&path).expect("read file");
    let name = std::path::Path::new(&path)
        .file_name()
        .unwrap()
        .to_string_lossy();
    let rep = osint_toolkit::meta::analyze(&bytes, &name);
    println!("{}", serde_json::to_string_pretty(&rep).unwrap());
}
