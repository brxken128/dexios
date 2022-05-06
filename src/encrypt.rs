use crate::encrypt::crypto::encrypt_bytes;
use crate::encrypt::file::get_file_bytes;
use crate::encrypt::file::overwrite_check;
use crate::encrypt::file::write_json_to_file;
use crate::encrypt::hashing::hash_data_blake3;
use anyhow::{Ok, Result};
use std::process::exit;
use std::time::Instant;

mod crypto;
mod file;
mod hashing;
mod password;

pub fn encrypt_file(
    input: &str,
    output: &str,
    keyfile: &str,
    sha_sum: bool,
    skip: bool,
) -> Result<()> {
    if !overwrite_check(output, skip)? {
        exit(0);
    }

    let raw_key = if !keyfile.is_empty() {
        get_file_bytes(keyfile)?
    } else {
        password::get_password_with_validation()?
    };

    let file_contents = get_file_bytes(input)?;

    let start_time = Instant::now();

    let data = encrypt_bytes(file_contents, raw_key);

    write_json_to_file(output, &data)?;

    let duration = start_time.elapsed();

    println!(
        "Encryption successful - written to {} [took {:.2}s]",
        output,
        duration.as_secs_f32()
    );

    if sha_sum {
        let start_time = Instant::now();
        let hash = hash_data_blake3(data)?;
        let duration = start_time.elapsed();
        println!(
            "Hash of the encrypted file is: {} [took {:.2}s]",
            hash,
            duration.as_secs_f32()
        );
    }

    Ok(())
}
