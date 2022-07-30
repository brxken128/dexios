use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    process::exit,
};

use super::prompt::{get_answer, overwrite_check};
use crate::{error, global::states::ForceMode, success, warn};
use anyhow::{Context, Result};
use dexios_core::header::HashingAlgorithm;
use dexios_core::header::{Header, HeaderVersion};

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

pub fn details(input: &str) -> Result<()> {
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let header_result = Header::deserialize(&mut input_file);

    if header_result.is_err() {
        return Err(anyhow::anyhow!(
            "This does not seem like a valid Dexios header, exiting"
        ));
    }

    let (header, aad) = header_result.unwrap();

    println!("Header version: {}", header.header_type.version);
    println!("Encryption algorithm: {}", header.header_type.algorithm);
    println!("Encryption mode: {}", header.header_type.mode);
    println!("Encryption nonce: {} (hex)", hex_encode(&header.nonce));
    println!("AAD: {} (hex)", hex_encode(&aad));

    match header.header_type.version {
        HeaderVersion::V1 => {
            println!("Salt: {} (hex)", hex_encode(&header.salt.unwrap()));
            println!("Hashing Algorithm: {}", HashingAlgorithm::Argon2id(1));
        }
        HeaderVersion::V2 => {
            println!("Salt: {} (hex)", hex_encode(&header.salt.unwrap()));
            println!("Hashing Algorithm: {}", HashingAlgorithm::Argon2id(2));
        }
        HeaderVersion::V3 => {
            println!("Salt: {} (hex)", hex_encode(&header.salt.unwrap()));
            println!("Hashing Algorithm: {}", HashingAlgorithm::Argon2id(3));
        }
        HeaderVersion::V4 | HeaderVersion::V5 => {
            for (i, keyslot) in header.keyslots.unwrap().iter().enumerate() {
                println!("Keyslot {}:", i);
                println!("  Hashing Algorithm: {}", keyslot.hash_algorithm);
                println!("  Salt: {} (hex)", hex_encode(&keyslot.salt));
                println!(
                    "  Master Key: {} (hex, encrypted)",
                    hex_encode(&keyslot.encrypted_key)
                );
                println!("  Master Key Nonce: {} (hex)", hex_encode(&keyslot.nonce));
            }
        }
    }

    Ok(())
}

// this function reads the header fromthe input file and writes it to the output file
// it's used for extracting an encrypted file's header for backups and such
// it implements a check to ensure the header is valid
pub fn dump(input: &str, output: &str, force: ForceMode) -> Result<()> {
    warn!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let header_result = Header::deserialize(&mut input_file);

    if header_result.is_err() {
        error!("File does not contain a valid Dexios header - exiting");
        drop(input_file);
        exit(1);
    }

    let (header, _) = header_result.context("Error unwrapping the header's result")?; // this should never happen

    if !overwrite_check(output, force)? {
        std::process::exit(0);
    }

    let mut output_file =
        File::create(output).with_context(|| format!("Unable to open output file: {}", output))?;

    header.write(&mut output_file)?;

    success!("Header dumped to {} successfully.", output);
    Ok(())
}

// this function reads the header from the input file
// it then writes the header to the start of the ouput file
// this can be used for restoring a dumped header to a file that had it's header stripped
// this does not work for files encrypted *with* a detached header
// it implements a check to ensure the header is valid before restoring to a file
pub fn restore(input: &str, output: &str, force: ForceMode) -> Result<()> {
    warn!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");
    let prompt = format!(
        "Are you sure you'd like to restore the header in {} to {}?",
        input, output
    );

    if !get_answer(&prompt, false, force == ForceMode::Force)? {
        exit(0);
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open header file: {}", input))?;

    let header_result = Header::deserialize(&mut input_file);

    if header_result.is_err() {
        error!("File does not contain a valid Dexios header - exiting");
        drop(input_file);
        exit(1);
    }

    let (header, _) = header_result.context("Error unwrapping the header's result")?;

    let mut output_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(output)
        .with_context(|| format!("Unable to open output file: {}", output))?;

    let mut header_bytes = vec![0u8; header.get_size() as usize];
    output_file
        .read(&mut header_bytes)
        .context("Unable to check for empty bytes at the start of the file")?;

    if !header_bytes.into_iter().all(|b| b == 0) {
        return Err(anyhow::anyhow!("No empty space found at the start of {}! It's either: not an encrypted file, it already contains a header, or it was encrypted in detached mode (and the header can't be restored)", output));
    }

    output_file
        .rewind()
        .context("Unable to rewind the output file!")?;

    header.write(&mut output_file)?;

    success!("Header restored to {} from {} successfully.", output, input);
    Ok(())
}

// this wipes the length of the header from the provided file
// the header must be intact for this to work, as the length varies between the versions
// it can be useful for storing the header separate from the file, to make an attacker's life that little bit harder
// it implements a check to ensure the header is valid before stripping
pub fn strip(input: &str, force: ForceMode) -> Result<()> {
    warn!("THIS FEATURE IS FOR ADVANCED USERS ONLY AND MAY RESULT IN A LOSS OF DATA - PROCEED WITH CAUTION");

    let prompt = format!("Are you sure you'd like to wipe the header for {}?", input);
    if !get_answer(&prompt, false, force == ForceMode::Force)? {
        exit(0);
    }

    let prompt = "This can be destructive! Make sure you dumped the header first. Would you like to continue?";
    if !get_answer(prompt, false, force == ForceMode::Force)? {
        exit(0);
    }

    let mut input_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(input)
        .with_context(|| format!("Unable to open input file: {}", input))?;

    let header_result = Header::deserialize(&mut input_file);

    if header_result.is_err() {
        error!("File does not contain a valid Dexios header - exiting");
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

    success!("Header stripped from {} successfully.", input);
    Ok(())
}
