use crate::prompt::get_answer;
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
