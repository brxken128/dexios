use crate::decrypt::crypto::decrypt_bytes_memory_mode_gcm;
use crate::decrypt::crypto::decrypt_bytes_stream_mode;
use crate::file::get_encrypted_data;
use crate::file::write_bytes;
use crate::global::BLOCK_SIZE;
use crate::global::CipherType;
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
pub fn memory_mode(
    input: &str,
    output: &str,
    keyfile: &str,
    hash_mode: bool,
    skip: bool,
    bench: bool,
    password: bool,
    _cipher_type: CipherType,
) -> Result<()> {
    if !overwrite_check(output, skip, bench)? {
        exit(0);
    }

    let read_start_time = Instant::now();
    let (salt, nonce, encrypted_data) = get_encrypted_data(input)?;
    let read_duration = read_start_time.elapsed();
    println!("Read {} [took {:.2}s]", input, read_duration.as_secs_f32());

    if hash_mode {
        let start_time = Instant::now();
        let hash = hash_data_blake3(&salt, &nonce, &encrypted_data)?;
        let duration = start_time.elapsed();
        println!(
            "Hash of the encrypted file is: {} [took {:.2}s]",
            hash,
            duration.as_secs_f32()
        );

        let answer = get_answer(
            "Would you like to continue with the decryption?",
            true,
            skip,
        )?;
        if !answer {
            exit(0);
        }
    }

    let raw_key = get_user_key(keyfile, false, password)?;

    println!(
        "Decrypting {} in memory mode (this may take a while)",
        input
    );
    let decrypt_start_time = Instant::now();
    let decrypted_bytes = decrypt_bytes_memory_mode_gcm(salt, nonce, &encrypted_data, raw_key)?;
    let decrypt_duration = decrypt_start_time.elapsed();
    println!(
        "Decryption successful! [took {:.2}s]",
        decrypt_duration.as_secs_f32()
    );

    if !bench {
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
pub fn stream_mode(
    input: &str,
    output: &str,
    keyfile: &str,
    hash_mode: bool,
    skip: bool,
    bench: bool,
    password: bool,
    cipher_type: CipherType,
) -> Result<()> {
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;
    let file_size = input_file
        .metadata()
        .with_context(|| format!("Unable to get input file metadata: {}", input))?
        .len();

    // +16 for GCM tag, +SALT_LEN to account for salt, +4 for the extra 4 bytes of nonce stored with each block
    // +8 to account for nonce itself
    if file_size
        <= (BLOCK_SIZE + 24 + SALT_LEN)
            .try_into()
            .context("Unable to parse stream block size as u64")?
    {
        println!(
            "Encrypted data size is less than the stream block size - redirecting to memory mode"
        );
        return memory_mode(input, output, keyfile, hash_mode, skip, bench, password, cipher_type);
    }

    if !overwrite_check(output, skip, bench)? {
        exit(0);
    }

    let mut output_file =
        File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;

    let raw_key = get_user_key(keyfile, false, password)?;

    println!(
        "Decrypting {} in stream mode (this may take a while)",
        input
    );
    let decrypt_start_time = Instant::now();
    decrypt_bytes_stream_mode(&mut input_file, &mut output_file, raw_key, bench, hash_mode, cipher_type)?;
    let decrypt_duration = decrypt_start_time.elapsed();
    println!(
        "Decryption successful! File saved as {} [took {:.2}s]",
        output,
        decrypt_duration.as_secs_f32(),
    );

    Ok(())
}
