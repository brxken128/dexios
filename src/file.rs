use crate::global::SALT_LEN;
use anyhow::{Context, Ok, Result};
use std::{
    fs::File,
    io::{BufReader, Read, Write},
};
use secrecy::SecretVec;
use secrecy::Secret;

// this takes the name/relative path of a file, and returns the bytes wrapped in a secret
pub fn get_bytes(name: &str) -> Result<Secret<Vec<u8>>> {
    let file = File::open(name).with_context(|| format!("Unable to open file: {}", name))?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .with_context(|| format!("Unable to read file: {}", name))?;
    Ok(SecretVec::new(data))
}

// this takes the name/relative path of a file, and reads it in the correct format
// this is used for memory-mode
// the first 16 bytes of the file are always the salt
// the next 12 bytes are always the nonce
// the rest of the data is the encrpted data
// all of these values are returned
pub fn get_encrypted_data(name: &str) -> Result<([u8; SALT_LEN], [u8; 12], Vec<u8>)> {
    let file = File::open(name).with_context(|| format!("Unable to open input file: {}", name))?;
    let mut reader = BufReader::new(file);

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; 12];
    let mut encrypted_data: Vec<u8> = Vec::new();

    let salt_size = reader
        .read(&mut salt)
        .with_context(|| format!("Unable to read salt from file: {}", name))?;
    let nonce_size = reader
        .read(&mut nonce)
        .with_context(|| format!("Unable to read nonce from file: {}", name))?;
    reader
        .read_to_end(&mut encrypted_data)
        .with_context(|| format!("Unable to read data from file: {}", name))?;

    if salt_size != SALT_LEN || nonce_size != 12 {
        return Err(anyhow::anyhow!(
            "Input file ({}) does not contain the correct amount of information",
            name
        ));
    }

    Ok((salt, nonce, encrypted_data))
}

// this writes the data, in the format that get_encrypted_data() can read
// this is used for memory-mode
// it takes the file name/relative path, salt, nonce and the data
// it first writes the 16 byte salt to the start of the file
// then it writes the 12 byte nonce
// and finally, it writes all of the data
pub fn write_encrypted_data(
    name: &str,
    salt: &[u8; 16],
    nonce: &[u8; 12],
    data: &[u8],
) -> Result<()> {
    let mut writer =
        File::create(name).with_context(|| format!("Unable to create output file: {}", name))?;
    writer
        .write_all(salt)
        .with_context(|| format!("Unable to write salt to output file: {}", name))?;
    writer
        .write_all(nonce)
        .with_context(|| format!("Unable to write nonce to output file: {}", name))?;
    writer
        .write_all(data)
        .with_context(|| format!("Unable to write data to output file: {}", name))?;
    writer
        .flush()
        .with_context(|| format!("Unable to flush the output file: {}", name))?;
    Ok(())
}

// this simply just writes bytes to the specified file
pub fn write_bytes(name: &str, bytes: &[u8]) -> Result<()> {
    let mut writer =
        File::create(name).with_context(|| format!("Unable to create output file: {}", name))?;
    writer
        .write_all(bytes)
        .with_context(|| format!("Unable to write to the output file: {}", name))?;
    writer
        .flush()
        .with_context(|| format!("Unable to flush the output file: {}", name))?;
    Ok(())
}
