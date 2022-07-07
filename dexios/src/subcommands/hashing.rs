use anyhow::Context;
use anyhow::{Ok, Result};
use paris::Logger;
use std::cell::RefCell;

use crate::domain;

// this hashes the input file
// it reads it in blocks, updates the hasher, and finalises/displays the hash
// it's used by hash-standalone mode
pub fn hash_stream(files: &[String]) -> Result<()> {
    let mut logger = Logger::new();
    for input in files {
        let mut input_file = std::fs::File::open(input)
            .with_context(|| format!("Unable to open file: {}", input))?;

        let hash = domain::hash::execute(domain::hash::Request {
            reader: RefCell::new(&mut input_file),
        })?;

        logger.success(format!("{}: {}", input, hash));
    }

    Ok(())
}
