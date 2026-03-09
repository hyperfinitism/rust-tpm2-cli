use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Write raw bytes to a file, creating it if necessary.
pub fn write_to_file(path: &Path, data: &[u8]) -> io::Result<()> {
    fs::write(path, data)
}

/// Print bytes as a lowercase hex string to stdout (no `0x` prefix), followed
/// by a newline.
pub fn print_hex(data: &[u8]) {
    println!("{}", hex::encode(data));
}

/// Write bytes to stdout in raw binary form.
pub fn write_binary_stdout(data: &[u8]) -> io::Result<()> {
    io::stdout().write_all(data)
}
