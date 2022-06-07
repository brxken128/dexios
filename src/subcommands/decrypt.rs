use super::key::get_secret;
use super::prompt::overwrite_check;
use crate::crypto::key::argon2_hash;
use crate::crypto::primitives::CipherMode;
use crate::global::header;
use crate::global::states::EraseMode;
use crate::global::states::HashMode;
use crate::global::states::HeaderFile;
use crate::global::structs::CryptoParams;
use anyhow::{Context, Result};
use paris::Logger;

use crate::crypto::primitives::cipher::Ciphers;
use aead::Payload;
use anyhow::anyhow;
use paris::success;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

use std::io::Read;
use std::io::Seek;
use std::process::exit;

use crate::crypto::primitives::stream::DecryptStreamCiphers;

// this function is for decrypting a file in memory mode
// it's responsible for  handling user-facing interactiveness, and calling the correct functions where appropriate
// it also manages using a detached header file if selected
pub fn memory_mode(
    input: &str,
    output: &str,
    header_file: &HeaderFile,
    params: &CryptoParams,
) -> Result<()> {
    let mut logger = Logger::new();

    if !overwrite_check(output, params.skip)? {
        exit(0);
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let (header, aad) = match header_file {
        HeaderFile::Some(contents) => {
            input_file
                .seek(std::io::SeekFrom::Start(64))
                .context("Unable to seek input file")?;
            let mut header_file = File::open(contents)
                .with_context(|| format!("Unable to open header file: {}", input))?;
            header::Header::deserialize(&mut header_file)?
        }
        HeaderFile::None => header::Header::deserialize(&mut input_file)?,
    };

    let read_start_time = Instant::now();

    let mut encrypted_data = Vec::new();
    input_file
        .read_to_end(&mut encrypted_data)
        .with_context(|| format!("Unable to read encrypted data from file: {}", input))?;
    let read_duration = read_start_time.elapsed();
    logger.success(format!(
        "Read {} [took {:.2}s]",
        input,
        read_duration.as_secs_f32()
    ));

    let raw_key = get_secret(&params.keyfile, false, params.password)?;

    logger.info(format!(
        "Using {} for decryption",
        header.header_type.algorithm
    ));

    logger.info(format!("Decrypting {} (this may take a while)", input));

    let mut output_file = File::create(output)?; // !!!attach context here
    
    let hash_start_time = Instant::now();
    let key = argon2_hash(raw_key, header.salt, &header.header_type.header_version)?;
    let hash_duration = hash_start_time.elapsed();
    success!(
        "Successfully hashed your key [took {:.2}s]",
        hash_duration.as_secs_f32()
    );

    let decrypt_start_time = Instant::now();

    let ciphers = Ciphers::initialize(key, header.header_type.algorithm)?;

    let payload = Payload {
        aad: &aad,
        msg: &encrypted_data,
    };

    let decrypted_bytes = match ciphers.decrypt(&header.nonce, payload) {
        Ok(decrypted_bytes) => decrypted_bytes,
        Err(_) => {
            return Err(anyhow!(
            "Unable to decrypt the data. This means either: you're using the wrong key, this isn't an encrypted file, or the header has been tampered with."
        ))
        }
    };

    let write_start_time = Instant::now();
    output_file.write_all(&decrypted_bytes)?;
    let write_duration = write_start_time.elapsed();
    success!("Wrote to file [took {:.2}s]", write_duration.as_secs_f32());
    let decrypt_duration = decrypt_start_time.elapsed();

    logger.success(format!(
        "Decryption successful! File saved as {} [took {:.2}s]",
        output,
        decrypt_duration.as_secs_f32(),
    ));

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&vec![input.to_string()])?;
    }

    if params.erase != EraseMode::IgnoreFile(0) {
        super::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}

// this function is for decrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if the input file isn't large enough
// it also manages using a detached header file if selected
pub fn stream_mode(
    input: &str,
    output: &str,
    header_file: &HeaderFile,
    params: &CryptoParams,
) -> Result<()> {
    let mut logger = Logger::new();

    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let (header, aad) = match header_file {
        HeaderFile::Some(contents) => {
            input_file
                .seek(std::io::SeekFrom::Start(64))
                .context("Unable to seek input file")?;
            let mut header_file = File::open(contents)
                .with_context(|| format!("Unable to open header file: {}", input))?;
            header::Header::deserialize(&mut header_file)?
        }
        HeaderFile::None => header::Header::deserialize(&mut input_file)?,
    };

    if header.header_type.cipher_mode == CipherMode::MemoryMode {
        drop(input_file);
        return memory_mode(input, output, header_file, params);
    }

    if !overwrite_check(output, params.skip)? {
        exit(0);
    }

    let raw_key = get_secret(&params.keyfile, false, params.password)?;

    let mut output_file = File::create(output)?; // !!!attach context here

    logger.info(format!(
        "Using {} for decryption",
        header.header_type.algorithm
    ));

    logger.info(format!("Decrypting {} (this may take a while)", input));

    let hash_start_time = Instant::now();
    let key = argon2_hash(raw_key, header.salt, &header.header_type.header_version)?;
    let hash_duration = hash_start_time.elapsed();
    success!(
        "Successfully hashed your key [took {:.2}s]",
        hash_duration.as_secs_f32()
    );

    let decrypt_start_time = Instant::now();

    let streams =
        DecryptStreamCiphers::initialize(key, &header.nonce, header.header_type.algorithm)?;

    streams.decrypt_file(&mut input_file, &mut output_file, &aad)?;

    let decrypt_duration = decrypt_start_time.elapsed();

    logger.success(format!(
        "Decryption successful! File saved as {} [took {:.2}s]",
        output,
        decrypt_duration.as_secs_f32(),
    ));

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&vec![input.to_string()])?;
    }

    if params.erase != EraseMode::IgnoreFile(0) {
        super::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}
