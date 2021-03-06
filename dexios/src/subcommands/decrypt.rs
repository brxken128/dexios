use std::process::exit;
use std::sync::Arc;
use std::time::Instant;

use super::prompt::overwrite_check;
use crate::global::states::{EraseMode, HashMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;

use anyhow::Result;
use paris::Logger;

use crate::domain::{self, storage::Storage};

// this function is for decrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if
// the header says so (backwards-compat)
// it also manages using a detached header file if selected
// it creates the stream object and uses the convenience function provided by dexios-core
pub fn stream_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    let mut logger = Arc::new(Logger::new());

    // 1. validate and prepare options
    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    if !overwrite_check(output, params.skip)? {
        exit(0);
    }

    let input_file = stor.read_file(input)?;
    let header_file = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(stor.read_file(path)?),
    };

    let raw_key = params.key.get_secret(&PasswordState::Direct)?;
    let output_file = stor
        .create_file(output)
        .or_else(|_| stor.write_file(output))?;

    if let Some(l) = Arc::get_mut(&mut logger) {
        l.info(format!("Decrypting {} (this may take a while)", input));
    }

    // 2. decrypt file
    let start_time = Instant::now();
    let mut inner_logger = logger.clone();
    domain::decrypt::execute(domain::decrypt::Request {
        header_reader: header_file.as_ref().and_then(|h| h.try_reader().ok()),
        reader: input_file.try_reader()?,
        writer: output_file.try_writer()?,
        raw_key,
        on_decrypted_header: Some(Box::new(move |header_type| {
            if let Some(l) = Arc::get_mut(&mut inner_logger) {
                l.info(format!("Using {} for decryption", header_type.algorithm));
            }
        })),
    })?;

    // 3. flush result
    stor.flush_file(&output_file)?;

    let decrypt_duration = start_time.elapsed();
    if let Some(l) = Arc::get_mut(&mut logger) {
        l.success(format!(
            "Decryption successful! File saved as {} [took {:.2}s]",
            output,
            decrypt_duration.as_secs_f32(),
        ));
    }

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[input.to_string()])?;
    }

    if let EraseMode::EraseFile(passes) = params.erase {
        super::erase::secure_erase(input, passes)?;
    }

    Ok(())
}
