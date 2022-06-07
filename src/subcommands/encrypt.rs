use super::key::get_secret;
use super::prompt::overwrite_check;
use crate::global::states::Algorithm;
use crate::global::states::EraseMode;
use crate::global::states::HashMode;
use crate::global::structs::CryptoParams;
use anyhow::Context;
use anyhow::{Ok, Result};
use paris::Logger;
use std::fs::File;
use std::process::exit;
use std::time::Instant;

// this function is for encrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if the input file isn't large enough
pub fn stream_mode(
    input: &str,
    output: &str,
    params: &CryptoParams,
    algorithm: Algorithm,
) -> Result<()> {
    let mut logger = Logger::new();

    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    if !overwrite_check(output, params.skip)? {
        exit(0);
    }

    let raw_key = get_secret(&params.keyfile, true, params.password)?;

    let mut output_file = File::create(output)?; // !!!attach context

    logger.info(format!("Using {} for encryption", algorithm));

    logger.info(format!("Encrypting {} (this may take a while)", input));

    let encrypt_start_time = Instant::now();

    let encryption_result =
        crate::crypto::encrypt::stream_mode(&mut input_file, &mut output_file, raw_key, algorithm);

    if encryption_result.is_err() {
        drop(output_file);
        std::fs::remove_file(output).context("Unable to remove the malformed file")?;
        return encryption_result;
    }

    let encrypt_duration = encrypt_start_time.elapsed();

    logger.success(format!(
        "Encryption successful! File saved as {} [took {:.2}s]",
        output,
        encrypt_duration.as_secs_f32(),
    ));

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&vec![output.to_string()])?;
    }

    if params.erase != EraseMode::IgnoreFile(0) {
        super::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}
