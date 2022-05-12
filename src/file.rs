use crate::prompt::get_answer;
use crate::structs::DexiosFile;
use anyhow::{Context, Ok, Result};
use std::fs::metadata;
use std::{
    fs::File,
    io::{BufReader, Read, Write},
};

pub fn get_file_bytes(name: &str) -> Result<Vec<u8>> {
    let file = File::open(name).context("Unable to open file")?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new(); // our file bytes
    reader
        .read_to_end(&mut data)
        .context("Unable to read the file")?;
    Ok(data)
}

pub fn get_encrypted_file_data(name: &str) -> Result<([u8; 256], [u8; 12], Vec<u8>)> {
    let file = File::open(name).context("Unable to open file")?;
    let mut reader = BufReader::new(file);

    let mut salt = [0u8; 256];
    let mut nonce = [0u8; 12];
    let mut encrypted_data: Vec<u8> = Vec::new();

    reader
        .read(&mut salt)
        .context("Unable to read salt from the file")?;
    reader
        .read(&mut nonce)
        .context("Unable to read nonce from the file")?;
    reader
        .read_to_end(&mut encrypted_data)
        .context("Unable to read data from the file")?;

    Ok((salt, nonce, encrypted_data))
}

pub fn write_encrypted_data_to_file(name: &str, data: &DexiosFile) -> Result<()> {
    let mut writer = File::create(name).context("Can't create output file")?;
    writer.write_all(&data.salt)?;
    writer.write_all(&data.nonce)?;
    writer.write_all(&data.data)?;
    writer.flush().context("Unable to flush output file")?;
    Ok(())
}

pub fn write_bytes_to_file(name: &str, bytes: Vec<u8>) -> Result<()> {
    let mut writer = File::create(name).context("Can't create output file")?;
    writer
        .write_all(&bytes)
        .context("Can't write to the output file")?;
    writer.flush().context("Unable to flush output file")?;
    Ok(())
}

pub fn overwrite_check(name: &str, skip: bool) -> Result<bool> {
    let answer = if metadata(name).is_ok() {
        let prompt = format!("{} already exists, would you like to overwrite?", name);
        get_answer(&prompt, true, skip).context("Unable to read provided answer")?
    } else {
        true
    };
    Ok(answer)
}
