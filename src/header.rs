use anyhow::{Context, Result};
use std::{fs::File, io::Write};
use std::io::Read;
use crate::{global::{HeaderType, DexiosMode, CipherType, SALT_LEN, SkipMode, BenchMode}, prompt::overwrite_check};

pub fn dump(input: &str, output: &str, header_info: HeaderType) -> Result<()> {
    let mut nonce_len = match header_info.cipher_type {
        CipherType::AesGcm => 12,
        CipherType::XChaCha20Poly1305 => 24,
    };

    if header_info.dexios_mode == DexiosMode::StreamMode {
        nonce_len -= 4; // the last 4 bytes are dynamic in stream mode
    }


    let mut salt = [0u8; SALT_LEN];
    let mut nonce = vec![0u8; nonce_len];


    let mut file = File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;
    let salt_size = file
        .read(&mut salt)
        .with_context(|| format!("Unable to read salt from file: {}", input))?;
    let nonce_size = file
        .read(&mut nonce)
        .with_context(|| format!("Unable to read nonce from file: {}", input))?;
    drop(file);
    if salt_size != SALT_LEN || nonce_size != nonce_len {
        return Err(anyhow::anyhow!(
            "Input file ({}) does not contain the correct amount of information",
            input
        ));
    }
    
    if !overwrite_check(output, SkipMode::ShowPrompts, BenchMode::WriteToFilesystem)? { // add -y support
        std::process::exit(0);
    }

    let mut output_file = File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;
    output_file.write_all(&salt).with_context(|| format!("Unable to write salt to output file: {}", output))?;
    output_file.write_all(&nonce).with_context(|| format!("Unable to write nonce to output file: {}", output))?;

    println!("Header dumped to {} successfully.", output);

    Ok(())
}