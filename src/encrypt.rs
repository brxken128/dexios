use crate::encrypt::crypto::encrypt_bytes;
use crate::encrypt::crypto::encrypt_bytes_stream;
use crate::encrypt::key::get_user_key;
use crate::file::get_file_bytes;
use crate::file::overwrite_check;
use crate::file::write_encrypted_data_to_file;
use crate::hashing::hash_data_blake3;
use anyhow::Context;
use anyhow::{Ok, Result};
use std::fs::File;
use std::process::exit;
use std::time::Instant;

mod crypto;
mod key;

pub fn encrypt_file(
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

    let raw_key = get_user_key(keyfile)?;

    let read_start_time = Instant::now();
    let file_contents = get_file_bytes(input)?;
    let read_duration = read_start_time.elapsed();
    println!("Read {} [took {:.2}s]", input, read_duration.as_secs_f32());

    println!(
        "Encrypting {} in legacy mode (this may take a while)",
        input
    );
    let encrypt_start_time = Instant::now();
    let data = encrypt_bytes(file_contents, raw_key);
    let encrypt_duration = encrypt_start_time.elapsed();
    println!(
        "Encryption successful! [took {:.2}s]",
        encrypt_duration.as_secs_f32()
    );

    if !bench {
        let write_start_time = Instant::now();
        write_encrypted_data_to_file(output, &data)?;
        let write_duration = write_start_time.elapsed();
        println!(
            "Wrote to {} [took {:.2}s]",
            output,
            write_duration.as_secs_f32()
        );
    }

    if hash_mode {
        let hash_start_time = Instant::now();
        let hash = hash_data_blake3(&data)?;
        let hash_duration = hash_start_time.elapsed();
        println!(
            "Hash of the encrypted file is: {} [took {:.2}s]",
            hash,
            hash_duration.as_secs_f32()
        );
    }

    Ok(())
}

pub fn encrypt_file_stream(
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

    let raw_key = get_user_key(keyfile)?;

    let mut input_file = File::open(input).context("Unable to open file")?;
    let mut output_file = File::create(output).context("Unable to open output file")?;

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
