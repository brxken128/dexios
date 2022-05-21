use anyhow::{Ok, Result};

use crate::global::{BLOCK_SIZE, SALT_LEN};

use anyhow::Context;
use std::io::Read;

// this simply just hashes the provided salt, nonce and data
// it returns a blake3 hash in hex format
pub fn hash_data_blake3(salt: &[u8; SALT_LEN], nonce: &[u8], data: &[u8]) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(salt);
    hasher.update(nonce);
    hasher.update(data);
    let hash = hasher.finalize().to_hex().to_string();
    Ok(hash)
}

pub fn hash_stream(input: &str) -> Result<()> {
    let mut input_file =
        std::fs::File::open(input).with_context(|| format!("Unable to open file: {}", input))?;

    println!("Hashing {} in stream mode (this may take a while)", input);
    let mut hasher = blake3::Hasher::new();

    let mut buffer = [0u8; BLOCK_SIZE];

    loop {
        let read_count = input_file
            .read(&mut buffer)
            .with_context(|| format!("Unable to read data from file: {}", input))?;
        hasher.update(&buffer[..read_count]);
        if read_count != BLOCK_SIZE {
            break;
        }
    }

    let hash = hasher.finalize().to_hex().to_string();

    println!("The hash for {} is: {}", input, hash);

    Ok(())
}

pub fn hash_memory(input: &str) -> Result<()> {
    let mut input_file =
        std::fs::File::open(input).with_context(|| format!("Unable to open file: {}", input))?;
    let mut data = Vec::new();

    input_file
        .read_to_end(&mut data)
        .with_context(|| format!("Unable to read data from file: {}", input))?;

    println!("Hashing {} in memory mode (this may take a while)", input);
    let hash = blake3::hash(&data).to_hex().to_string();

    println!("The hash for {} is: {}", input, hash);

    Ok(())
}
