use crate::domain::{self, storage::Storage};
use anyhow::Result;
use paris::Logger;
use std::sync::Arc;
use std::time::Instant;

use super::prompt::get_answer;

// this function securely erases a file
// read the docs for some caveats with file-erasure on flash storage
// it takes the file name/relative path, and the number of times to go over the file's contents with random bytes
pub fn secure_erase(input: &str, passes: i32) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    let file = stor.read_file(input)?;
    if file.is_dir()
        && !get_answer(
            "This is a directory, would you like to erase all files within it?",
            false,
            false,
        )?
    {
        std::process::exit(0);
    }

    let mut logger = Logger::new();
    let start_time = Instant::now();
    logger.loading(format!(
        "Erasing {} with {} passes (this may take a while)",
        input, passes
    ));

    if file.is_dir() {
        domain::erase_dir::execute(stor, domain::erase_dir::Request { file, passes })?;

        logger.success(format!("Deleted directory: {}", input));
    } else {
        domain::erase::execute(
            stor,
            domain::erase::Request {
                path: input,
                passes,
            },
        )?;
    }

    let duration = start_time.elapsed();
    logger.done().success(format!(
        "Erased {} successfully [took {:.2}s]",
        input,
        duration.as_secs_f32()
    ));

    Ok(())
}
