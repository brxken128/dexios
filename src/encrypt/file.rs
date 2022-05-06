use anyhow::{Context, Ok, Result};
use std::{
    fs::File,
    io::{BufReader, Read, Write},
};

use crate::structs::DexiosFile;

pub fn get_file_bytes(name: &str) -> Result<Vec<u8>> {
    let file = File::open(name).context("Unable to open file")?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new(); // our file bytes
    reader
        .read_to_end(&mut data)
        .context("Unable to read the file")?;
    Ok(data)
}

pub fn write_json_to_file(name: &str, data: &DexiosFile) -> Result<()> {
    let mut writer = File::create(name).context("Can't create output file")?;
    serde_json::to_writer(&writer, data).context("Can't write to the output file")?;
    writer.flush().context("Unable to flush output file")?;
    Ok(())
}
