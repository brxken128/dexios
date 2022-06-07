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

        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();

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
