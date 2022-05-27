use crate::encrypt::crypto::encrypt_bytes_memory_mode;
use crate::encrypt::crypto::encrypt_bytes_stream_mode;
use crate::file::get_bytes;
use crate::global::parameters::Algorithm;
use crate::global::parameters::BenchMode;
use crate::global::parameters::CryptoParams;
use crate::global::parameters::EraseMode;
use crate::global::parameters::OutputFile;
use crate::global::BLOCK_SIZE;
use crate::key::get_secret;
use crate::prompt::overwrite_check;
use anyhow::Context;
use anyhow::{Ok, Result};
use std::fs::File;
use std::process::exit;
use std::time::Instant;

mod crypto;

// this function is for encrypting a file in memory mode
// it's responsible for  handling user-facing interactiveness, and calling the correct functions where appropriate
pub fn memory_mode(
    input: &str,
    output: &str,
    params: &CryptoParams,
    algorithm: Algorithm,
) -> Result<()> {
    if !overwrite_check(output, params.skip, params.bench)? {
        exit(0);
    }

    let raw_key = get_secret(&params.keyfile, true, params.password)?;

    let read_start_time = Instant::now();
    let file_contents = get_bytes(input)?;
    let read_duration = read_start_time.elapsed();
    println!("Read {} [took {:.2}s]", input, read_duration.as_secs_f32());

    println!(
        "Encrypting {} in memory mode with {} (this may take a while)",
        input, algorithm
    );

    let mut output_file = if params.bench == BenchMode::WriteToFilesystem {
        OutputFile::Some(
            File::create(output)
                .with_context(|| format!("Unable to open output file: {}", output))?,
        )
    } else {
        OutputFile::None
    };

    let encrypt_start_time = Instant::now();
    encrypt_bytes_memory_mode(
        file_contents,
        &mut output_file,
        raw_key,
        params.bench,
        params.hash_mode,
        algorithm,
    )?;
    let encrypt_duration = encrypt_start_time.elapsed();
    println!(
        "Encryption successful! [took {:.2}s]",
        encrypt_duration.as_secs_f32()
    );

    if params.erase != EraseMode::IgnoreFile(0) {
        crate::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}

// this function is for encrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if the input file isn't large enough
pub fn stream_mode(
    input: &str,
    output: &str,
    params: &CryptoParams,
    algorithm: Algorithm,
) -> Result<()> {
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;
    let file_size = input_file
        .metadata()
        .with_context(|| format!("Unable to get input file metadata: {}", input))?
        .len();

    if file_size
        <= BLOCK_SIZE
            .try_into()
            .context("Unable to parse stream block size as u64")?
    {
        return memory_mode(input, output, params, algorithm);
    }

    if !overwrite_check(output, params.skip, params.bench)? {
        exit(0);
    }

    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name in stream mode."
        ));
    }

    let raw_key = get_secret(&params.keyfile, true, params.password)?;

    let mut output_file = if params.bench == BenchMode::WriteToFilesystem {
        OutputFile::Some(
            File::create(output)
                .with_context(|| format!("Unable to open output file: {}", output))?,
        )
    } else {
        OutputFile::None
    };

    println!(
        "Encrypting {} in stream mode with {} (this may take a while)",
        input, algorithm
    );
    let encrypt_start_time = Instant::now();

    let encryption_result = encrypt_bytes_stream_mode(
        &mut input_file,
        &mut output_file,
        raw_key,
        params.bench,
        params.hash_mode,
        algorithm,
    );

    if encryption_result.is_err() {
        drop(output_file);
        if params.bench == BenchMode::WriteToFilesystem {
            std::fs::remove_file(output).context("Unable to remove the malformed file")?;
        }
        return encryption_result
    }

    let encrypt_duration = encrypt_start_time.elapsed();
    match params.bench {
        BenchMode::WriteToFilesystem => {
            println!(
                "Encryption successful! File saved as {} [took {:.2}s]",
                output,
                encrypt_duration.as_secs_f32(),
            );
        }
        BenchMode::BenchmarkInMemory => {
            println!(
                "Encryption successful! [took {:.2}s]",
                encrypt_duration.as_secs_f32(),
            );
        }
    }

    if params.erase != EraseMode::IgnoreFile(0) {
        crate::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}
