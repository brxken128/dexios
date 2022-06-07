use crate::global::protected::Secret;
use anyhow::{Context, Ok, Result};
use std::{fs::File, io::Read};

// this takes the name/relative path of a file, and returns the bytes wrapped in a secret
pub fn get_bytes(name: &str) -> Result<Secret<Vec<u8>>> {
    let mut file = File::open(name).with_context(|| format!("Unable to open file: {}", name))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .with_context(|| format!("Unable to read file: {}", name))?;
    Ok(Secret::new(data))
}
