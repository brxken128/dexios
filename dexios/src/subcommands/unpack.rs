use crate::subcommands::prompt::get_answer;
use std::sync::{Arc, Mutex};

use anyhow::Result;

use domain::storage::Storage;

use crate::global::{
    states::{ForceMode, HeaderLocation, PasswordState, PrintMode},
    structs::CryptoParams,
};
use crate::{info, success, warn};
use std::path::PathBuf;
use std::time::Instant;

// this first decrypts the input file to a temporary zip file
// it then unpacks that temporary zip file to the target directory
// once finished, it erases the temporary file to avoid any residual data
#[allow(clippy::module_name_repetitions)]
pub fn unpack(
    input: &str,  // encrypted zip file
    output: &str, // directory
    print_mode: PrintMode,
    params: CryptoParams, // params for decrypt function
) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    let input_file = stor.read_file(input)?;
    let header_file = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(stor.read_file(path)?),
    };

    let raw_key = params.key.get_secret(&PasswordState::Direct)?;

    let files_count = Arc::new(Mutex::new(0));
    let cb_files_count = files_count.clone();
    let cb_output = output.to_string();

    let zip_start_time = Instant::now();
    domain::unpack::execute(
        stor,
        domain::unpack::Request {
            header_reader: header_file.as_ref().and_then(|h| h.try_reader().ok()),
            reader: input_file.try_reader()?,
            output_dir_path: PathBuf::from(output),
            raw_key,
            on_decrypted_header: Some(Box::new(move |header_type| {
                info!("Using {} for decryption", header_type.algorithm);
            })),
            on_archive_info: Some(Box::new(move |fc| {
                *cb_files_count.lock().unwrap() = fc;

                info!("Decompressing {} items into {}", fc, cb_output);
            })),
            on_zip_file: Some(Box::new(move |file_path| {
                let file_name = file_path
                    .file_name()
                    .expect("Unable to convert file name to OsStr")
                    .to_str()
                    .expect("Unable to convert file name's OsStr to &str")
                    .to_string();

                if std::fs::metadata(file_path).is_ok() {
                    let answer = get_answer(
                        &format!("{} already exists, would you like to overwrite?", file_name),
                        true,
                        params.force == ForceMode::Force,
                    )
                    .expect("Unable to read answer");
                    if !answer {
                        warn!("Skipping {}", file_name);
                        return false;
                    }
                }

                if print_mode == PrintMode::Verbose {
                    warn!("Extracting {}", file_name);
                }

                true
            })),
        },
    )?;

    /*
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
                    params.force == ForceMode::Force,
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

    */

    let zip_duration = zip_start_time.elapsed();
    success!(
        "Extracted {} items to {} [took {:.2}s]",
        *files_count.lock().unwrap(),
        output,
        zip_duration.as_secs_f32()
    );

    success!(
        "Unpacking Successful! You will find your files in {}",
        output
    );

    Ok(())
}
