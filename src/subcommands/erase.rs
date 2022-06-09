use anyhow::{Context, Result};
use paris::Logger;
use rand::RngCore;
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Instant,
};

use super::prompt::get_answer;

// this function securely erases a file
// read the docs for some caveats with file-erasure on flash storage
// it takes the file name/relative path, and the number of times to go over the file's contents with random bytes
#[allow(clippy::module_name_repetitions)]
pub fn secure_erase(input: &str, passes: i32) -> Result<()> {
    let mut logger = Logger::new();

    let start_time = Instant::now();
    let file = File::open(input).with_context(|| format!("Unable to open file: {}", input))?;
    let data = file
        .metadata()
        .with_context(|| format!("Unable to get input file metadata: {}", input))?;

    if data.is_dir() {
        drop(file);
        if !get_answer("This is a directory, would you like to erase all files within it?", false, false)? {
            std::process::exit(0);
        }
        let (files, _) = crate::file::get_paths_in_dir(input, crate::global::states::DirectoryMode::Recursive, &Vec::<String>::new(), &crate::global::states::HiddenFilesMode::Include, &crate::global::states::PrintMode::Quiet)?;
        for file in files {
            secure_erase(file.to_str().context("Unable to get &str from PathBuf")?, passes)?;
        }
        std::fs::remove_dir_all(input).context("Unable to delete directory")?;
        logger.success(format!("Deleted directory: {}", input));
        return Ok(())
    }

    let file = File::create(input).with_context(|| format!("Unable to open file: {}", input))?;
    let mut writer = BufWriter::new(file);

    logger.loading(format!(
        "Erasing {} with {} passes (this may take a while)",
        input, passes
    ));

    for _ in 0..passes {
        if data.len() < 512 {
            // if file is smaller than the 512 byte "block"
            let mut buf = vec![
                0;
                data.len()
                    .try_into()
                    .context("Unable to get file size as usize")?
            ];
            rand::thread_rng().fill_bytes(&mut buf);
            writer
                .write_all(&buf)
                .with_context(|| format!("Unable to overwrite with random bytes: {}", input))?;
        } else {
            for _ in 0..data.len() / 512 {
                // for every 512 byte "block"
                let mut buf = vec![0; 512];
                rand::thread_rng().fill_bytes(&mut buf);
                writer
                    .write_all(&buf)
                    .with_context(|| format!("Unable to overwrite with random bytes: {}", input))?;
            }
            if (data.len() % 512) != 0 {
                // if not perfectly divisible by 512
                let mut buf = vec![
                    0;
                    (512 % data.len())
                        .try_into()
                        .context("Unable to get file size as usize")?
                ];
                rand::thread_rng().fill_bytes(&mut buf);
                writer
                    .write_all(&buf)
                    .with_context(|| format!("Unable to overwrite with random bytes: {}", input))?;
            }
        }

        writer
            .flush()
            .with_context(|| format!("Unable to flush file: {}", input))?;
    }

    // overwrite with zeros for good measure
    let file = File::create(input).with_context(|| format!("Unable to open file: {}", input))?;
    let mut writer = BufWriter::new(file);
    for _ in 0..data.len() {
        writer
            .write(&[0])
            .with_context(|| format!("Unable to overwrite with zeros: {}", input))?;
    }
    writer
        .flush()
        .with_context(|| format!("Unable to flush file: {}", input))?;
    drop(writer);

    let mut file = File::create(input).context("Unable to open the input file")?;
    file.set_len(0)
        .with_context(|| format!("Unable to truncate file: {}", input))?;
    file.flush()
        .with_context(|| format!("Unable to flush file: {}", input))?;
    drop(file);

    std::fs::remove_file(input).with_context(|| format!("Unable to remove file: {}", input))?;

    let duration = start_time.elapsed();

    logger.done().success(format!(
        "Erased {} successfully [took {:.2}s]",
        input,
        duration.as_secs_f32()
    ));

    Ok(())
}
