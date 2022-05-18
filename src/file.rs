use crate::global::{DexiosFile, SALT_LEN};
use crate::prompt::get_answer;
use anyhow::{Context, Ok, Result};
use std::fs::metadata;
use std::{
    fs::File,
    io::{BufReader, Read, Write},
};

pub fn get_file_bytes(name: &str) -> Result<Vec<u8>> {
    let file = File::open(name).with_context(|| format!("Unable to open file: {}", name))?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new(); // our file bytes
    reader
        .read_to_end(&mut data)
        .with_context(|| format!("Unable to read file: {}", name))?;
    Ok(data)
}

pub fn get_encrypted_file_data(name: &str) -> Result<([u8; SALT_LEN], [u8; 12], Vec<u8>)> {
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

pub fn write_encrypted_data_to_file(name: &str, data: &DexiosFile) -> Result<()> {
    let mut writer =
        File::create(name).with_context(|| format!("Unable to create output file: {}", name))?;
    writer
        .write_all(&data.salt)
        .with_context(|| format!("Unable to write salt to output file: {}", name))?;
    writer
        .write_all(&data.nonce)
        .with_context(|| format!("Unable to write nonce to output file: {}", name))?;
    writer
        .write_all(&data.data)
        .with_context(|| format!("Unable to write data to output file: {}", name))?;
    writer
        .flush()
        .with_context(|| format!("Unable to flush the output file: {}", name))?;
    Ok(())
}

pub fn write_bytes_to_file(name: &str, bytes: Vec<u8>) -> Result<()> {
    let mut writer =
        File::create(name).with_context(|| format!("Unable to create output file: {}", name))?;
    writer
        .write_all(&bytes)
        .with_context(|| format!("Unable to write to the output file: {}", name))?;
    writer
        .flush()
        .with_context(|| format!("Unable to flush the output file: {}", name))?;
    Ok(())
}

pub fn overwrite_check(name: &str, skip: bool) -> Result<bool> {
    let answer = if metadata(name).is_ok() {
        let prompt = format!("{} already exists, would you like to overwrite?", name);
        get_answer(&prompt, true, skip)?
    } else {
        true
    };
    Ok(answer)
}
