use crate::decrypt::crypto::decrypt_bytes_memory_mode;
use crate::decrypt::crypto::decrypt_bytes_stream_mode;
use crate::global::enums::BenchMode;
use crate::global::enums::CipherMode;
use crate::global::enums::EraseMode;
use crate::global::enums::HeaderFile;
use crate::global::enums::OutputFile;
use crate::global::structs::CryptoParams;
use crate::key::get_secret;
use crate::prompt::overwrite_check;
use anyhow::{Context, Ok, Result};
use paris::Logger;
use std::fs::File;

use std::io::Read;
use std::process::exit;
use std::time::Instant;
mod crypto;

// this function is for decrypting a file in memory mode
// it's responsible for  handling user-facing interactiveness, and calling the correct functions where appropriate
// it also manages using a detached header file if selected
pub fn memory_mode(
    input: &str,
    output: &str,
    header_file: &HeaderFile,
    params: &CryptoParams,
) -> Result<()> {
    let mut logger = Logger::new();

    if !overwrite_check(output, params.skip, params.bench)? {
        exit(0);
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let header = match header_file {
        HeaderFile::Some(contents) => {
            let mut header_file = File::open(contents)
                .with_context(|| format!("Unable to open header file: {}", input))?;
            input_file
                .read_exact(&mut [0u8; 64])
                .with_context(|| format!("Unable to seek input file: {}", input))?;
            crate::header::read_from_file(&mut header_file)?
        }
        HeaderFile::None => crate::header::read_from_file(&mut input_file)?,
    };

    let read_start_time = Instant::now();

    let mut encrypted_data = Vec::new();
    input_file
        .read_to_end(&mut encrypted_data)
        .with_context(|| format!("Unable to read encrypted data from file: {}", input))?;
    let read_duration = read_start_time.elapsed();
    logger.success(format!(
        "Read {} [took {:.2}s]",
        input,
        read_duration.as_secs_f32()
    ));

    let raw_key = get_secret(&params.keyfile, false, params.password)?;

    logger.loading(format!(
        "Decrypting {} in memory mode with {} (this may take a while)",
        input, header.header_type.algorithm,
    ));

    let mut output_file = if params.bench == BenchMode::WriteToFilesystem {
        OutputFile::Some(
            File::create(output)
                .with_context(|| format!("Unable to open output file: {}", output))?,
        )
    } else {
        OutputFile::None
    };

    let decrypt_start_time = Instant::now();
    decrypt_bytes_memory_mode(
        &header,
        &encrypted_data,
        &mut output_file,
        raw_key,
        params.bench,
        params.hash_mode,
    )?;
    let decrypt_duration = decrypt_start_time.elapsed();
    logger.done().success(format!(
        "Decryption successful! [took {:.2}s]",
        decrypt_duration.as_secs_f32()
    ));

    if params.erase != EraseMode::IgnoreFile(0) {
        crate::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}

// this function is for decrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if the input file isn't large enough
// it also manages using a detached header file if selected
pub fn stream_mode(
    input: &str,
    output: &str,
    header_file: &HeaderFile,
    params: &CryptoParams,
) -> Result<()> {
    let mut logger = Logger::new();

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let header = match header_file {
        HeaderFile::Some(contents) => {
            let mut header_file = File::open(contents)
                .with_context(|| format!("Unable to open header file: {}", input))?;
            input_file
                .read_exact(&mut [0u8; 64])
                .with_context(|| format!("Unable to seek input file: {}", input))?;
            crate::header::read_from_file(&mut header_file)?
        }
        HeaderFile::None => crate::header::read_from_file(&mut input_file)?,
    };

    if header.header_type.cipher_mode == CipherMode::MemoryMode {
        drop(input_file);
        return memory_mode(input, output, header_file, params);
    }

    if !overwrite_check(output, params.skip, params.bench)? {
        exit(0);
    }

    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name in stream mode."
        ));
    }

    let raw_key = get_secret(&params.keyfile, false, params.password)?;

    let mut output_file = if params.bench == BenchMode::WriteToFilesystem {
        OutputFile::Some(
            File::create(output)
                .with_context(|| format!("Unable to open output file: {}", output))?,
        )
    } else {
        OutputFile::None
    };

    logger.loading(format!(
        "Decrypting {} in stream mode with {} (this may take a while)",
        input, header.header_type.algorithm,
    ));
    let decrypt_start_time = Instant::now();
    let decryption_result = decrypt_bytes_stream_mode(
        &mut input_file,
        &mut output_file,
        raw_key,
        &header,
        params.bench,
        params.hash_mode,
    );

    if decryption_result.is_err() {
        drop(output_file);
        if params.bench == BenchMode::WriteToFilesystem {
            std::fs::remove_file(output).context("Unable to remove the malformed file")?;
        }
        return decryption_result;
    }

    let decrypt_duration = decrypt_start_time.elapsed();

    match params.bench {
        BenchMode::WriteToFilesystem => {
            logger.done().success(format!(
                "Decryption successful! File saved as {} [took {:.2}s]",
                output,
                decrypt_duration.as_secs_f32(),
            ));
        }
        BenchMode::BenchmarkInMemory => {
            logger.done().success(format!(
                "Decryption successful! [took {:.2}s]",
                decrypt_duration.as_secs_f32(),
            ));
        }
    }

    if params.erase != EraseMode::IgnoreFile(0) {
        crate::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}
