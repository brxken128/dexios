use anyhow::{Context, Ok, Result};
use dexios_core::protected::Protected;
use std::io::Read;

// this takes the name/relative path of a file, and returns the bytes in a "protected" wrapper
pub fn get_bytes<R: Read>(reader: &mut R) -> Result<Protected<Vec<u8>>> {
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .context("Unable to read data")?;
    Ok(Protected::new(data))
}
