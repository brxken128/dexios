use std::{fs::File, io::Seek};

use anyhow::{Ok, Result};

use crate::global::DexiosFile;

pub fn hash_data_blake3(data: &DexiosFile) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&data.salt);
    hasher.update(&data.nonce);
    hasher.update(&data.data);
    let hash = hasher.finalize().to_hex().to_string();
    Ok(hash)
}

pub fn hash_data_blake3_stream(file: &mut File) -> Result<String> {
    let mut hasher = blake3::Hasher::new();




    file.seek(std::io::SeekFrom::Start(0))?;
    todo!()
}