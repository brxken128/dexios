use std::process::exit;
use std::sync::Arc;

use crate::cli::prompt::overwrite_check;
use crate::global::states::{EraseMode, HashMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;

use anyhow::Result;

use domain::storage::Storage;

// this function is for decrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if
// the header says so (backwards-compat)
// it also manages using a detached header file if selected
// it creates the stream object and uses the convenience function provided by dexios-core
pub fn stream_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    // 1. validate and prepare options
    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    if !overwrite_check(output, params.force)? {
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

    // 2. decrypt file
    domain::decrypt::execute(domain::decrypt::Request {
        header_reader: header_file.as_ref().and_then(|h| h.try_reader().ok()),
        reader: input_file.try_reader()?,
        writer: output_file.try_writer()?,
        raw_key,
        on_decrypted_header: None,
    })?;

    // 3. flush result
    stor.flush_file(&output_file)?;

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[input.to_string()])?;
    }

    if let EraseMode::EraseFile(passes) = params.erase {
        super::erase::secure_erase(input, passes, params.force)?;
    }

    Ok(())
}
