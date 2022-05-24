use crate::{
    global::{BenchMode, CipherType, DexiosMode, HeaderType, SkipMode, SALT_LEN},
    prompt::{get_answer, overwrite_check},
};
use anyhow::{Context, Result};
use std::{fs::File, io::Write};
use std::{fs::OpenOptions, io::Read, process::exit};

fn calc_nonce_len(header_info: &HeaderType) -> usize {
    let mut nonce_len = match header_info.cipher_type {
        CipherType::AesGcm => 12,
        CipherType::XChaCha20Poly1305 => 24,
    };

    if header_info.dexios_mode == DexiosMode::StreamMode {
        nonce_len -= 4; // the last 4 bytes are dynamic in stream mode
    }

    nonce_len
}

pub fn dump(input: &str, output: &str, skip: SkipMode, header_info: &HeaderType) -> Result<()> {
    println!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
    let nonce_len = calc_nonce_len(header_info);

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = vec![0u8; nonce_len];

    let mut file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;
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

    if !overwrite_check(output, skip, BenchMode::WriteToFilesystem)? {
        std::process::exit(0);
    }

    let mut output_file =
        File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;
    output_file
        .write_all(&salt)
        .with_context(|| format!("Unable to write salt to output file: {}", output))?;
    output_file
        .write_all(&nonce)
        .with_context(|| format!("Unable to write nonce to output file: {}", output))?;

    println!("Header dumped to {} successfully.", output);
    Ok(())
}

pub fn restore(input: &str, output: &str, skip: SkipMode, header_info: &HeaderType) -> Result<()> {
    println!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
    let prompt = format!("Are you sure you'd like to restore the header in {} to {}, and that it was created with {} in {}?", input, output, header_info.cipher_type, header_info.dexios_mode);
    if !get_answer(&prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let nonce_len = calc_nonce_len(header_info);

    let mut buffer = vec![0u8; SALT_LEN + nonce_len];
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open header file: {}", input))?;
    input_file
        .read(&mut buffer)
        .with_context(|| format!("Unable to read salt and nonce from file: {}", input))?;

    let mut output_file = OpenOptions::new()
        .write(true)
        .open(output)
        .with_context(|| format!("Unable to open output file: {}", output))?;

    output_file
        .write_all(&buffer)
        .with_context(|| format!("Unable to write header to file: {}", output))?;

    println!("Header restored to {} from {} successfully.", output, input);
    Ok(())
}

pub fn strip(input: &str, skip: SkipMode, header_info: &HeaderType) -> Result<()> {
    println!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
    let prompt = format!(
        "Are you sure you'd like to wipe the header for {}, and that it was created with {} in {}?",
        input, header_info.cipher_type, header_info.dexios_mode
    );
    if !get_answer(&prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let nonce_len = calc_nonce_len(header_info);

    let buffer = vec![0u8; SALT_LEN + nonce_len];

    let mut file = OpenOptions::new()
        .write(true)
        .open(input)
        .with_context(|| format!("Unable to open input file: {}", input))?;

    file.write_all(&buffer)
        .with_context(|| format!("Unable to wipe header for file: {}", input))?;

    println!("Header stripped from {} successfully.", input);
    Ok(())
}
