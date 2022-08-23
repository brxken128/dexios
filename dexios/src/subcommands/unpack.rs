use crate::cli::prompt::get_answer;
use std::sync::Arc;

use anyhow::Result;

use domain::storage::Storage;

use crate::global::{
    states::{HeaderLocation, PasswordState, PrintMode},
    structs::CryptoParams,
};
use crate::{info, warn};
use std::path::PathBuf;

// this first decrypts the input file to a temporary zip file
// it then unpacks that temporary zip file to the target directory
// once finished, it erases the temporary file to avoid any residual data
#[allow(clippy::module_name_repetitions)]
#[allow(clippy::needless_pass_by_value)]
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

    domain::unpack::execute(
        stor,
        domain::unpack::Request {
            header_reader: header_file.as_ref().and_then(|h| h.try_reader().ok()),
            reader: input_file.try_reader()?,
            output_dir_path: PathBuf::from(output),
            raw_key,
            on_decrypted_header: None,
            on_archive_info: None,
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
                        params.force,
                    )
                    .expect("Unable to read answer");
                    if !answer {
                        warn!("Skipping {}", file_name);
                        return false;
                    }
                }

                if print_mode == PrintMode::Verbose {
                    info!("Extracting {}", file_name);
                }

                true
            })),
        },
    )?;

    Ok(())
}
