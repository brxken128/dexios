use anyhow::{Context, Result};
use rand::distributions::{Alphanumeric, DistString};

use crate::{
    global::{
        states::{PrintMode, SkipMode},
        structs::CryptoParams,
    },
    info, success, warn,
};
use std::fs::File;
use std::path::PathBuf;
use std::{str::FromStr, time::Instant};

use super::prompt::get_answer;

// this first decrypts the input file to a temporary zip file
// it then unpacks that temporary zip file to the target directory
// once finished, it erases the temporary file to avoid any residual data
#[allow(clippy::module_name_repetitions)]
pub fn unpack(
    input: &str,  // encrypted zip file
    output: &str, // directory
    print_mode: &PrintMode,
    params: &CryptoParams, // params for decrypt function
) -> Result<()> {
    let random_extension: String = Alphanumeric.sample_string(&mut rand::thread_rng(), 8);

    // this is the name of the decrypted zip file
    let tmp_name = format!("{}.{}", input, random_extension); // e.g. "input.kjHSD93l"

    super::decrypt::stream_mode(input, &tmp_name, params)?;

    let zip_start_time = Instant::now();
    let file = File::open(&tmp_name).context("Unable to open temporary archive")?;
    let mut archive = zip::ZipArchive::new(file)
        .context("Temporary archive can't be opened, is it a zip file?")?;

    match std::fs::create_dir(output) {
        Ok(_) => info!("Created output directory: {}", output),
        Err(_) => info!("Output directory ({}) already exists", output),
    };

    let file_count = archive.len();

    info!("Decompressing {} items into {}", file_count, output);

    for i in 0..file_count {
        // recreate the directory structure first
        let mut full_path = PathBuf::from_str(output)
            .context("Unable to create a PathBuf from your output directory")?;

        let item = archive.by_index(i).context("Unable to index the archive")?;

        match item.enclosed_name() {
            Some(path) => full_path.push(path),
            None => continue,
        };

        // zip slip prevention
        if item.name().contains("..") {
            continue;
        }

        #[cfg(windows)] // zip slip prevention
        if item.name().contains(".\\") {
            continue;
        }

        if item.is_dir() {
            // if it's a directory, recreate the structure
            std::fs::create_dir_all(full_path).context("Unable to create an output directory")?;
        }
    }

    for i in 0..file_count {
        let mut full_path = PathBuf::from_str(output)
            .context("Unable to create a PathBuf from your output directory")?;

        let mut file = archive.by_index(i).context("Unable to index the archive")?;
        match file.enclosed_name() {
            Some(path) => full_path.push(path),
            None => continue,
        };

        // zip slip prevention
        if file.name().contains("..") {
            continue;
        }

        #[cfg(windows)] // zip slip prevention
        if file.name().contains(".\\") {
            continue;
        }

        if file.is_file() {
            // this must be a file
            let file_name: String = full_path
                .clone()
                .file_name()
                .context("Unable to convert file name to OsStr")?
                .to_str()
                .context("Unable to convert file name's OsStr to &str")?
                .to_string();
            if std::fs::metadata(full_path.clone()).is_ok() {
                let answer = get_answer(
                    &format!("{} already exists, would you like to overwrite?", file_name),
                    true,
                    params.skip == SkipMode::HidePrompts,
                )?;
                if !answer {
                    warn!("Skipping {}", file_name);
                    continue;
                }
            }
            if print_mode == &PrintMode::Verbose {
                warn!("Extracting {}", file_name);
            }

            let mut output_file =
                File::create(full_path).context("Error creating an output file")?;
            std::io::copy(&mut file, &mut output_file)
                .context("Error copying data out of archive to the target file")?;
        }
    }

    let zip_duration = zip_start_time.elapsed();
    success!(
        "Extracted {} items to {} [took {:.2}s]",
        file_count,
        output,
        zip_duration.as_secs_f32()
    );

    super::erase::secure_erase(&tmp_name, 2)?; // cleanup the tmp file

    success!(
        "Unpacking Successful! You will find your files in {}",
        output
    );

    Ok(())
}
