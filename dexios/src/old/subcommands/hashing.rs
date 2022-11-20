use anyhow::Context;
use anyhow::Result;
use std::cell::RefCell;

use crate::success;

// this hashes the input file
// it reads it in blocks, updates the hasher, and finalises/displays the hash
// it's used by hash-standalone mode
pub fn hash_stream(files: &[String]) -> Result<()> {
    for input in files {
        let mut input_file = std::fs::File::open(input)
            .with_context(|| format!("Unable to open file: {}", input))?;

        let hash = domain::hash::execute(
            domain::hasher::Blake3Hasher::default(),
            domain::hash::Request {
                reader: RefCell::new(&mut input_file),
            },
        )?;

        success!("{}: {}", input, hash);
    }

    Ok(())
}
