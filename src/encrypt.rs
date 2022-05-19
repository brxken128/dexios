use crate::encrypt::crypto::encrypt_bytes;
use crate::encrypt::crypto::encrypt_bytes_stream;
use crate::file::get_bytes;
use crate::file::overwrite_check;
use crate::file::write_encrypted_data;
use crate::global::BLOCK_SIZE;
use crate::hashing::hash_data_blake3;
use crate::key::get_user_key_encrypt;
use anyhow::Context;
use anyhow::{Ok, Result};
use std::fs::File;
use std::process::exit;
use std::time::Instant;

mod crypto;

pub fn memory_mode(
    input: &str,
    output: &str,
    keyfile: &str,
    hash_mode: bool,
    skip: bool,
    bench: bool,
) -> Result<()> {
    if !overwrite_check(output, skip)? {
        exit(0);
    }

    let raw_key = get_user_key_encrypt(keyfile)?;

    let read_start_time = Instant::now();
    let file_contents = get_bytes(input)?;
    let read_duration = read_start_time.elapsed();
    println!("Read {} [took {:.2}s]", input, read_duration.as_secs_f32());

    println!(
        "Encrypting {} in memory mode (this may take a while)",
        input
    );
    let encrypt_start_time = Instant::now();
    let (salt, nonce, data) = encrypt_bytes(file_contents, raw_key)?;
    let encrypt_duration = encrypt_start_time.elapsed();
    println!(
        "Encryption successful! [took {:.2}s]",
        encrypt_duration.as_secs_f32()
    );

    if !bench {
        let write_start_time = Instant::now();
        write_encrypted_data(output, &salt, &nonce, &data)?;
        let write_duration = write_start_time.elapsed();
        println!(
            "Wrote to {} [took {:.2}s]",
            output,
            write_duration.as_secs_f32()
        );
    }

    if hash_mode {
        let hash_start_time = Instant::now();
        let hash = hash_data_blake3(&salt, &nonce, &data)?;
        let hash_duration = hash_start_time.elapsed();
        println!(
            "Hash of the encrypted file is: {} [took {:.2}s]",
            hash,
            hash_duration.as_secs_f32()
        );
    }

    Ok(())
}

pub fn stream_mode(
    input: &str,
    output: &str,
    keyfile: &str,
    hash_mode: bool,
    skip: bool,
    bench: bool,
) -> Result<()> {
    if !overwrite_check(output, skip)? {
        exit(0);
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;
    let file_size = input_file
        .metadata()
        .with_context(|| format!("Unable to get input file metadata: {}", input))?
        .len();

    if file_size <= BLOCK_SIZE.try_into().unwrap() {
        println!("Input file size is less than the stream block size - redirecting to memory mode");
        return memory_mode(input, output, keyfile, hash_mode, skip, bench);
    }

    let mut output_file =
        File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;

    let raw_key = get_user_key_encrypt(keyfile)?;

    println!(
        "Encrypting {} in stream mode (this may take a while)",
        input
    );
    let encrypt_start_time = Instant::now();
    encrypt_bytes_stream(&mut input_file, &mut output_file, raw_key, bench, hash_mode)?;
    let encrypt_duration = encrypt_start_time.elapsed();
    println!(
        "Encryption successful! [took {:.2}s]",
        encrypt_duration.as_secs_f32()
    );

    Ok(())
}
