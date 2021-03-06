use super::prompt::overwrite_check;
use crate::global::states::{EraseMode, HashMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;
use anyhow::Result;
use dexios_core::header::{HashingAlgorithm, HeaderType, HEADER_VERSION};
use dexios_core::primitives::{Algorithm, Mode};
use paris::Logger;
use std::process::exit;
use std::sync::Arc;
use std::time::Instant;

use crate::domain::{self, storage::Storage};

// this function is for encrypting a file in stream mode
// it handles any user-facing interactiveness, opening files
// it creates the stream object and uses the convenience function provided by dexios-core
pub fn stream_mode(
    input: &str,
    output: &str,
    params: &CryptoParams,
    algorithm: Algorithm,
) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    let mut logger = Logger::new();

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
    let raw_key = params.key.get_secret(&PasswordState::Validate)?;
    let output_file = stor
        .create_file(output)
        .or_else(|_| stor.write_file(output))?;

    let header_file = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => {
            if !overwrite_check(path, params.skip)? {
                exit(0);
            }

            Some(stor.create_file(path).or_else(|_| stor.write_file(path))?)
        }
    };

    logger.info(format!("Using {} for encryption", algorithm));
    logger.info(format!("Encrypting {} (this may take a while)", input));

    let start_time = Instant::now();

    // 2. encrypt file
    let req = domain::encrypt::Request {
        reader: input_file.try_reader()?,
        writer: output_file.try_writer()?,
        header_writer: header_file.as_ref().and_then(|f| f.try_writer().ok()),
        raw_key,
        header_type: HeaderType {
            version: HEADER_VERSION,
            mode: Mode::StreamMode,
            algorithm,
        },
        hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
    };
    domain::encrypt::execute(req)?;

    // 3. flush result
    if let Some(header_file) = header_file {
        stor.flush_file(&header_file)?;
    }
    stor.flush_file(&output_file)?;

    let encrypt_duration = start_time.elapsed();
    logger.success(format!(
        "Encryption successful! File saved as {} [took {:.2}s]",
        output,
        encrypt_duration.as_secs_f32(),
    ));

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[output.to_string()])?;
    }

    if let EraseMode::EraseFile(passes) = params.erase {
        super::erase::secure_erase(input, passes)?;
    }

    Ok(())
}
