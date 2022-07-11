use crate::domain;
use anyhow::{Context, Result};
use paris::Logger;
use std::{fs::File, time::Instant};

use super::prompt::get_answer;

// this function securely erases a file
// read the docs for some caveats with file-erasure on flash storage
// it takes the file name/relative path, and the number of times to go over the file's contents with random bytes
#[allow(clippy::module_name_repetitions)]
pub fn secure_erase(input: &str, passes: i32) -> Result<()> {
    let mut logger = Logger::new();

    let start_time = Instant::now();
    let file = File::open(input).with_context(|| format!("Unable to open file: {}", input))?;
    let file_meta = file
        .metadata()
        .with_context(|| format!("Unable to get input file metadata: {}", input))?;

    if file_meta.is_dir() {
        drop(file);
        if !get_answer(
            "This is a directory, would you like to erase all files within it?",
            false,
            false,
        )? {
            std::process::exit(0);
        }
        let (files, _) = crate::file::get_paths_in_dir(
            input,
            crate::global::states::DirectoryMode::Recursive,
            &Vec::<String>::new(),
            &crate::global::states::HiddenFilesMode::Include,
            &crate::global::states::PrintMode::Quiet,
        )?;
        for file in files {
            secure_erase(
                file.to_str().context("Unable to get &str from PathBuf")?,
                passes,
            )?;
        }
        std::fs::remove_dir_all(input).context("Unable to delete directory")?;
        logger.success(format!("Deleted directory: {}", input));
        return Ok(());
    }

    logger.loading(format!(
        "Erasing {} with {} passes (this may take a while)",
        input, passes
    ));

    // TODO: It is necessary to raise it to a higher level
    let stor = domain::storage::FileStorage;

    domain::erase::execute(
        &stor,
        domain::erase::Request {
            path: input,
            passes,
        },
    )?;

    let duration = start_time.elapsed();

    logger.done().success(format!(
        "Erased {} successfully [took {:.2}s]",
        input,
        duration.as_secs_f32()
    ));

    Ok(())
}
