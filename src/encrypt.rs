use crate::encrypt::crypto::encrypt_bytes;
use crate::file::get_file_bytes;
use crate::file::overwrite_check;
use crate::file::write_encrypted_data_to_file;
use crate::hashing::hash_data_blake3;
use aes_gcm::aead::stream::EncryptorLE31;
use anyhow::Context;
use anyhow::{Ok, Result};
use std::process::exit;
use std::time::Instant;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::fs::File;

use crate::structs::DexiosFile;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key};
use argon2::Argon2;
use argon2::Params;
use rand::{prelude::StdRng, Rng, RngCore, SeedableRng};

mod crypto;
mod password;

pub fn encrypt_file(
    input: &str,
    output: &str,
    keyfile: &str,
    sha_sum: bool,
    skip: bool,
    bench: bool,
) -> Result<()> {
    if !overwrite_check(output, skip)? {
        exit(0);
    }

    // add a check for "output file is larger than recommended, would you like to use stream encryption?"

    let raw_key = if !keyfile.is_empty() {
        println!("Reading key from {}", keyfile);
        get_file_bytes(keyfile)?
    } else if std::env::var("DEXIOS_KEY").is_ok() {
        println!("Reading key from DEXIOS_KEY environment variable");
        std::env::var("DEXIOS_KEY")
            .context("Unable to read DEXIOS_KEY from environment variable")?
            .into_bytes()
    } else {
        println!("Reading key from stdin");
        password::get_password_with_validation()?
    };

    let read_start_time = Instant::now();
    let file_contents = get_file_bytes(input)?;
    let read_duration = read_start_time.elapsed();
    println!("Read {} [took {:.2}s]", input, read_duration.as_secs_f32());

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

    if sha_sum {
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
    sha_sum: bool,
    skip: bool,
    bench: bool,
) -> Result<()> {
    if !overwrite_check(output, skip)? {
        exit(0);
    }

    let raw_key = if !keyfile.is_empty() {
        println!("Reading key from {}", keyfile);
        get_file_bytes(keyfile)?
    } else if std::env::var("DEXIOS_KEY").is_ok() {
        println!("Reading key from DEXIOS_KEY environment variable");
        std::env::var("DEXIOS_KEY")
            .context("Unable to read DEXIOS_KEY from environment variable")?
            .into_bytes()
    } else {
        println!("Reading key from stdin");
        password::get_password_with_validation()?
    };

    let mut input = File::open(input).context("Unable to open file")?;
    
    let mut output = File::create(output).context("Unable to open output file")?;

    let nonce_bytes = rand::thread_rng().gen::<[u8; 8]>(); // only 8 because the last 4 are for GCM
    let nonce = GenericArray::from_slice(nonce_bytes.as_slice());

    let (key, salt) = crypto::gen_key(raw_key);
    let cipher_key = Key::from_slice(key.as_slice());

    let cipher = Aes256Gcm::new(cipher_key);
    let mut stream = EncryptorLE31::from_aead(cipher, &nonce);

    output.write_all(&salt)?;
    output.write_all(&nonce_bytes)?;

    let mut buffer = [0u8; 1024];

    loop {
        let read_count = input.read(&mut buffer)?;
        if read_count == 1024 {
            let encrypted_data = stream.encrypt_next(buffer.as_slice()).unwrap();
            output.write_all(&encrypted_data)?;
        } else { // if we read something less than 1024, and have hit the end of the file
            let encrypted_data = stream.encrypt_last(buffer.as_slice()).unwrap();
            output.write_all(&encrypted_data)?;
            break;
        }
    }
    output.flush()?;

    Ok(())
}
