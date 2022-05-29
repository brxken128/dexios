use crate::global::BLOCK_SIZE;
use anyhow::Context;
use anyhow::{Ok, Result};
use paris::Logger;
use std::io::Read;

// this hashes the input file
// it reads it in blocks, updates the hasher, and finalises/displays the hash
// it's used by hash-standalone mode
pub fn hash_stream(files: &Vec<String>) -> Result<()> {
    let mut logger = Logger::new();
    for input in files {
        let mut input_file = std::fs::File::open(input)
            .with_context(|| format!("Unable to open file: {}", input))?;

        let file_size = std::fs::metadata(input)
            .with_context(|| format!("Unable to get file metadata: {}", input))?;

        if file_size.len()
            <= BLOCK_SIZE
                .try_into()
                .context("Unable to parse stream block size as u64")?
        {
            drop(input_file);
            hash_memory(&input, &mut logger)?;
            continue;
        }

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

        logger.success(format!("{}: {}", input, hash));
    }

    Ok(())
}

// this hashes the input file
// it reads the file all at once, hashes it and displays the hash
// it's used by hash-standalone mode when the input file isn't large enough for streaming mode
pub fn hash_memory(input: &str, logger: &mut Logger) -> Result<()> {
    let mut input_file =
        std::fs::File::open(input).with_context(|| format!("Unable to open file: {}", input))?;
    let mut data = Vec::new();

    input_file
        .read_to_end(&mut data)
        .with_context(|| format!("Unable to read data from file: {}", input))?;

    let hash = blake3::hash(&data).to_hex().to_string();

    logger.success(format!("{}: {}", input, hash));

    Ok(())
}
