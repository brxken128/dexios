use crate::subcommands::prompt::get_answer;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

    let files_count = Arc::new(AtomicUsize::new(0));

    // Prepare the data to move in the `on_archive_info` callback
    let files_count_clone = files_count.clone();
    let output_clone = output.to_string();

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
                files_count_clone.store(fc, Ordering::Relaxed);

                info!("Decompressing {} items into {}", fc, output_clone);
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

    let zip_duration = zip_start_time.elapsed();
    success!(
        "Extracted {} items to {} [took {:.2}s]",
        files_count.load(Ordering::Relaxed),
        output,
        zip_duration.as_secs_f32()
    );

    success!(
        "Unpacking Successful! You will find your files in {}",
        output
    );

    Ok(())
}
