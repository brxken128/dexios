use crate::{
    global::parameters::{BenchMode, CipherMode, CipherType, HeaderType, SkipMode, HeaderData},
    global::SALT_LEN,
    prompt::{get_answer, overwrite_check},
};
use anyhow::{Context, Result};
use std::{fs::File, io::Write};
use std::{fs::OpenOptions, io::Read, process::exit};

fn calc_nonce_len(header_info: &HeaderType) -> usize {
    let mut nonce_len = match header_info.cipher_type {
        CipherType::XChaCha20Poly1305 => 24,
        CipherType::AesGcm => 12,
    };

    if header_info.cipher_mode == CipherMode::StreamMode {
        nonce_len -= 4; // the last 4 bytes are dynamic in stream mode
    }

    nonce_len
}

fn serialise(header_info: &HeaderType) -> ([u8; 2], [u8; 2]) {
    let cipher_info = match header_info.cipher_type {
        CipherType::XChaCha20Poly1305 => {
            let info: [u8; 2] = [0x00, 0x00];
            info
        },
        CipherType::AesGcm => {
            let info: [u8; 2] = [0x00, 0x01];
            info
        },
    };

    let mode_info = match header_info.cipher_mode {
        CipherMode::StreamMode => {
            let info: [u8; 2] = [0x0A, 0x00];
            info
        },
        CipherMode::MemoryMode => {
            let info: [u8; 2] = [0x0A, 0x01];
            info
        },
    };

    (cipher_info, mode_info)
}

pub fn write_to_file(file: &mut File, salt: &[u8; SALT_LEN], nonce: &[u8], header_info: &HeaderType) -> Result<()> {
    let nonce_len = calc_nonce_len(header_info);
    let padding = vec![0u8; 28 - nonce_len];
    let (cipher_info, mode_info) = serialise(header_info);

    file.write_all(&cipher_info)?;
    file.write_all(&mode_info)?; // 4 bytes total
    file.write_all(salt)?; // 20 bytes total
    file.write_all(&[0; 16])?; // 36 bytes total (28 remaining)
    file.write_all(nonce)?; // (28 - nonce_len remaining)
    file.write_all(&padding)?; // this has reached the 64 bytes
    Ok(())
}

fn deserialise(cipher_info: &[u8; 2], mode_info: &[u8; 2]) -> Result<HeaderType> {
    let cipher_type = match cipher_info {
        [0x00, 0x00] => CipherType::XChaCha20Poly1305,
        [0x00, 0x01] => CipherType::AesGcm,
        _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
    };

    let cipher_mode = match mode_info {
        [0x0A, 0x00] => CipherMode::StreamMode,
        [0x0A, 0x01] => CipherMode::MemoryMode,
        _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
    };

    Ok(HeaderType { cipher_type, cipher_mode })
}


pub fn read_from_file(file: &mut File) -> Result<HeaderData> {
    let mut cipher_info = [0u8; 2];
    let mut mode_info = [0u8; 2];
    let mut salt = [0u8; SALT_LEN];

    file.read(&mut cipher_info)?;
    file.read(&mut mode_info)?;

    let header_info = deserialise(&cipher_info, &mode_info)?;
    let nonce_len = calc_nonce_len(&header_info);
    let mut nonce = vec![0u8; nonce_len];
    let mut _padding = vec![0u8; 28 - nonce_len];

    file.read(&mut salt)?;
    file.read(&mut [0; 16])?; // read and subsequently discard the next 16 bytes
    file.read(&mut nonce)?;
    file.read(&mut _padding)?;

    Ok(HeaderData { header_type: header_info, nonce, salt })
}

pub fn dump(input: &str, output: &str, skip: SkipMode) -> Result<()> {
    println!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");

    let mut header = [0u8; 64];

    let mut file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;
    file.read_exact(&mut header)?;

    if !overwrite_check(output, skip, BenchMode::WriteToFilesystem)? {
        std::process::exit(0);
    }

    let mut output_file =
        File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;
    output_file
        .write_all(&header)
        .with_context(|| format!("Unable to write header to output file: {}", output))?;

    println!("Header dumped to {} successfully.", output);
    Ok(())
}

pub fn restore(input: &str, output: &str, skip: SkipMode) -> Result<()> {
    println!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
    let prompt = format!("Are you sure you'd like to restore the header in {} to {}?", input, output);
    if !get_answer(&prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let mut header = vec![0u8; 64];
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open header file: {}", input))?;
    input_file
        .read(&mut header)
        .with_context(|| format!("Unable to read header from file: {}", input))?;

    let mut output_file = OpenOptions::new()
        .write(true)
        .open(output)
        .with_context(|| format!("Unable to open output file: {}", output))?;

    output_file
        .write_all(&header)
        .with_context(|| format!("Unable to write header to file: {}", output))?;

    println!("Header restored to {} from {} successfully.", output, input);
    Ok(())
}

pub fn strip(input: &str, skip: SkipMode) -> Result<()> {
    println!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
    let prompt = format!(
        "Are you sure you'd like to wipe the header for {}?",
        input
    );
    if !get_answer(&prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let buffer = vec![0u8; 64];

    let mut file = OpenOptions::new()
        .write(true)
        .open(input)
        .with_context(|| format!("Unable to open input file: {}", input))?;

    file.write_all(&buffer)
        .with_context(|| format!("Unable to wipe header for file: {}", input))?;

    println!("Header stripped from {} successfully.", input);
    Ok(())
}
