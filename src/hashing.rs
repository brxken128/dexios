use crate::global::BLOCK_SIZE;
use anyhow::Context;
use anyhow::{Ok, Result};
use std::io::Read;

// this hashes the input file
// it reads it in blocks, updates the hasher, and finalises/displays the hash
// it's used by hash-standalone mode
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

// this hashes the input file
// it reads the file all at once, hashes it and displays the hash
// it's used by hash-standalone mode when the input file isn't large enough for streaming mode
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
