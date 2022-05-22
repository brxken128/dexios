use crate::decrypt::crypto::decrypt_bytes_memory_mode;
use crate::decrypt::crypto::decrypt_bytes_stream_mode;
use crate::file::get_encrypted_data;
use crate::file::write_bytes;
use crate::global::BenchMode;
use crate::global::HashMode;
use crate::global::Parameters;
use crate::global::SkipMode;
use crate::global::BLOCK_SIZE;
use crate::global::SALT_LEN;
use crate::hashing::hash_data_blake3;
use crate::key::get_user_key;
use crate::prompt::get_answer;
use crate::prompt::overwrite_check;
use anyhow::{Context, Ok, Result};
use std::fs::File;

use std::process::exit;
use std::time::Instant;
mod crypto;

// this function is for decrypting a file in memory mode
// it's responsible for  handling user-facing interactiveness, and calling the correct functions where appropriate
pub fn memory_mode(input: &str, output: &str, keyfile: &str, params: &Parameters) -> Result<()> {
    if !overwrite_check(output, params.skip, params.bench)? {
        exit(0);
    }

    let read_start_time = Instant::now();
    let (salt, nonce, encrypted_data) = get_encrypted_data(input, params.cipher_type)?;
    let read_duration = read_start_time.elapsed();
    println!("Read {} [took {:.2}s]", input, read_duration.as_secs_f32());

    if params.hash_mode == HashMode::EmitHash {
        let start_time = Instant::now();
        let hash = hash_data_blake3(&salt, &nonce, &encrypted_data)?;
        let duration = start_time.elapsed();
        println!(
            "Hash of the encrypted file is: {} [took {:.2}s]",
            hash,
            duration.as_secs_f32()
        );

        let skip_if_hidden = params.skip == SkipMode::HidePrompts;

        let answer = get_answer(
            "Would you like to continue with the decryption?",
            true,
            skip_if_hidden,
        )?;
        if !answer {
            exit(0);
        }
    }

    let raw_key = get_user_key(keyfile, false, params.password)?;

    println!(
        "Decrypting {} in memory mode (this may take a while)",
        input
    );
    let decrypt_start_time = Instant::now();
    let decrypted_bytes =
        decrypt_bytes_memory_mode(salt, &nonce, &encrypted_data, raw_key, params.cipher_type)?;
    let decrypt_duration = decrypt_start_time.elapsed();
    println!(
        "Decryption successful! [took {:.2}s]",
        decrypt_duration.as_secs_f32()
    );

    if params.bench == BenchMode::WriteToFilesystem {
        let write_start_time = Instant::now();
        write_bytes(output, &decrypted_bytes)?;
        let write_duration = write_start_time.elapsed();
        println!(
            "Wrote to {} [took {:.2}s]",
            output,
            write_duration.as_secs_f32()
        );
    }

    Ok(())
}

// this function is for decrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if the input file isn't large enough
pub fn stream_mode(input: &str, output: &str, keyfile: &str, params: &Parameters) -> Result<()> {
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;
    let file_size = input_file
        .metadata()
        .with_context(|| format!("Unable to get input file metadata: {}", input))?
        .len();

    // +16 for AEAD tag, +SALT_LEN to account for salt, +4 for the extra 4 bytes of nonce stored with each block
    // +8 to account for nonce itself (assuming the smallest nonce, which is aes-256-gcm's)
    if file_size
        <= (BLOCK_SIZE + 24 + SALT_LEN)
            .try_into()
            .context("Unable to parse stream block size as u64")?
    {
        println!(
            "Encrypted data size is less than the stream block size - redirecting to memory mode"
        );
        return memory_mode(input, output, keyfile, params);
    }

    if !overwrite_check(output, params.skip, params.bench)? {
        exit(0);
    }

    let mut output_file =
        File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;

    let raw_key = get_user_key(keyfile, false, params.password)?;

    println!(
        "Decrypting {} in stream mode with {} (this may take a while)",
        input, params.cipher_type,
    );
    let decrypt_start_time = Instant::now();
    decrypt_bytes_stream_mode(
        &mut input_file,
        &mut output_file,
        raw_key,
        params.bench,
        params.hash_mode,
        params.cipher_type,
    )?;
    let decrypt_duration = decrypt_start_time.elapsed();
    println!(
        "Decryption successful! File saved as {} [took {:.2}s]",
        output,
        decrypt_duration.as_secs_f32(),
    );

    Ok(())
}
