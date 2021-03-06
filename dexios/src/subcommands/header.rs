use std::{
    fs::{File, OpenOptions},
    io::{Seek, Write},
    process::exit,
};

use super::prompt::{get_answer, overwrite_check};
use crate::global::states::SkipMode;
use anyhow::{Context, Result};
use dexios_core::header::HashingAlgorithm;
use dexios_core::header::{Header, HeaderVersion};
use paris::Logger;

pub fn details(input: &str) -> Result<()> {
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let header_result = Header::deserialize(&mut input_file);

    if header_result.is_err() {
        return Err(anyhow::anyhow!(
            "This does not seem like a valid Dexios header, exiting"
        ));
    }

    let (header, _) = header_result.unwrap();

    println!("Header version: {}", header.header_type.version);
    println!("Encryption algorithm: {}", header.header_type.algorithm);
    println!("Encryption mode: {}", header.header_type.mode);
    println!("Encryption nonce: {} (hex)", hex::encode(header.nonce));

    // could make use of the AAD too

    match header.header_type.version {
        HeaderVersion::V1 => {
            println!("Salt: {} (hex)", hex::encode(header.salt.unwrap()));
            println!("Hashing Algorithm: {}", HashingAlgorithm::Argon2id(1));
        }
        HeaderVersion::V2 => {
            println!("Salt: {} (hex)", hex::encode(header.salt.unwrap()));
            println!("Hashing Algorithm: {}", HashingAlgorithm::Argon2id(2));
        }
        HeaderVersion::V3 => {
            println!("Salt: {} (hex)", hex::encode(header.salt.unwrap()));
            println!("Hashing Algorithm: {}", HashingAlgorithm::Argon2id(3));
        }
        HeaderVersion::V4 | HeaderVersion::V5 => {
            for (i, keyslot) in header.keyslots.unwrap().iter().enumerate() {
                println!("Keyslot {}:", i);
                println!("  Hashing Algorithm: {}", keyslot.hash_algorithm);
                println!("  Salt: {} (hex)", hex::encode(keyslot.salt));
                println!(
                    "  Master Key: {} (hex, encrypted)",
                    hex::encode(keyslot.encrypted_key)
                );
                println!(
                    "  Master Key's Nonce: {} (hex)",
                    hex::encode(keyslot.nonce.clone())
                );
            }
        }
    }

    Ok(())
}

// this function dumps the first 64/128 bytes of
// the input file into the output file
// it's used for extracting an encrypted file's header for backups and such
// it implements a check to ensure the header is valid
pub fn dump(input: &str, output: &str, skip: SkipMode) -> Result<()> {
    let mut logger = Logger::new();
    logger.warn("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let header_result = Header::deserialize(&mut input_file);

    if header_result.is_err() {
        logger.error("File does not contain a valid Dexios header - exiting");
        drop(input_file);
        exit(1);
    }

    let (header, _) = header_result.context("Error unwrapping the header's result")?; // this should never happen

    if !overwrite_check(output, skip)? {
        std::process::exit(0);
    }

    let mut output_file =
        File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;

    header.write(&mut output_file)?;

    logger.success(format!("Header dumped to {} successfully.", output));
    Ok(())
}

// this function reads the first 64/128 bytes (header) from the input file
// and then overwrites the first 64/128 bytes of the output file with it
// this can be used for restoring a dumped header to a file that had it's header stripped
// it implements a check to ensure the header is valid before restoring to a file
pub fn restore(input: &str, output: &str, skip: SkipMode) -> Result<()> {
    let mut logger = Logger::new();
    logger.warn("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
    let prompt = format!(
        "Are you sure you'd like to restore the header in {} to {}?",
        input, output
    );

    if !get_answer(&prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open header file: {}", input))?;

    let header_result = Header::deserialize(&mut input_file);

    if header_result.is_err() {
        logger.error("File does not contain a valid Dexios header - exiting");
        drop(input_file);
        exit(1);
    }

    let (header, _) = header_result.context("Error unwrapping the header's result")?; // this should never happen

    let mut output_file = OpenOptions::new()
        .write(true)
        .open(output)
        .with_context(|| format!("Unable to open output file: {}", output))?;

    header.write(&mut output_file)?;

    logger.success(format!(
        "Header restored to {} from {} successfully.",
        output, input
    ));
    Ok(())
}

// this wipes the first 64/128 bytes (header) from the provided file
// it can be useful for storing the header separate from the file, to make an attacker's life that little bit harder
// it implements a check to ensure the header is valid before stripping
pub fn strip(input: &str, skip: SkipMode) -> Result<()> {
    let mut logger = Logger::new();
    logger.warn("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");

    let prompt = format!("Are you sure you'd like to wipe the header for {}?", input);
    if !get_answer(&prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let prompt = "This can be destructive! Make sure you dumped the header first. Would you like to continue?";
    if !get_answer(prompt, false, skip == SkipMode::HidePrompts)? {
        exit(0);
    }

    let mut input_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(input)
        .with_context(|| format!("Unable to open input file: {}", input))?;

    let header_result = Header::deserialize(&mut input_file);

    if header_result.is_err() {
        logger.error("File does not contain a valid Dexios header - exiting");
        drop(input_file);
        exit(1);
    }

    let (header, _) = header_result.context("Error unwrapping the header's result")?; // this should never happen
    let header_size: i64 = header
        .get_size()
        .try_into()
        .context("Error getting header's size as i64")?;

    input_file
        .seek(std::io::SeekFrom::Current(-header_size))
        .context("Unable to seek back to the start of the file")?;

    input_file
        .write_all(&vec![
            0;
            header_size
                .try_into()
                .context("Error getting header's size as usize")?
        ])
        .with_context(|| format!("Unable to wipe header for file: {}", input))?;

    logger.success(format!("Header stripped from {} successfully.", input));
    Ok(())
}
