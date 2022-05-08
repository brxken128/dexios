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
    bench: bool,
) -> Result<()> {
    if !overwrite_check(output, skip)? {
        exit(0);
    }

    let raw_key = if !keyfile.is_empty() {
        get_file_bytes(keyfile)?
    } else {
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
        write_json_to_file(output, &data)?;
        let write_duration = write_start_time.elapsed();
        println!(
            "Wrote to {} [took {:.2}s]",
            output,
            write_duration.as_secs_f32()
        );
    }

    if sha_sum {
        let hash_start_time = Instant::now();
        let hash = hash_data_blake3(data)?;
        let hash_duration = hash_start_time.elapsed();
        println!(
            "Hash of the encrypted file is: {} [took {:.2}s]",
            hash,
            hash_duration.as_secs_f32()
        );
    }

    Ok(())
}
