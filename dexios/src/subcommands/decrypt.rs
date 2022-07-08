use super::prompt::overwrite_check;
use crate::global::states::EraseMode;
use crate::global::states::HashMode;
use crate::global::states::HeaderLocation;
use crate::global::states::PasswordState;
use crate::global::structs::CryptoParams;
use anyhow::{Context, Result};
use dexios_core::header;
use dexios_core::header::HeaderVersion;
use dexios_core::key::argon2id_hash;
use dexios_core::primitives::Mode;
use dexios_core::protected::Protected;
use dexios_core::Zeroize;
use paris::Logger;

use dexios_core::cipher::Ciphers;
use dexios_core::Payload;
use paris::success;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

use std::io::Read;
use std::io::Seek;
use std::process::exit;

use dexios_core::stream::DecryptionStreams;

// this function is for decrypting a file in memory mode
// it's responsible for  handling user-facing interactiveness, and calling the correct functions where appropriate
// it also manages using a detached header file if selected
// it creates the Cipher object, and uses that for decryption
// it then writes the decrypted data to the file
pub fn memory_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    let mut logger = Logger::new();

    if !overwrite_check(output, params.skip)? {
        exit(0);
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let (header, aad) = match &params.header_location {
        HeaderLocation::Detached(contents) => {
            let mut header_file = File::open(contents)
                .with_context(|| format!("Unable to open header file: {}", input))?;
            let (header, aad) = header::Header::deserialize(&mut header_file)?;
            input_file
                .seek(std::io::SeekFrom::Start(header.get_size()))
                .context("Unable to seek input file")?;
            (header, aad)
        }
        HeaderLocation::Embedded => header::Header::deserialize(&mut input_file)?,
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

    let raw_key = params.key.get_secret(&PasswordState::Direct)?;

    logger.info(format!(
        "Using {} for decryption",
        header.header_type.algorithm
    ));

    logger.info(format!("Decrypting {} (this may take a while)", input));

    let mut output_file = File::create(output).context("Unable to create output file")?;

    let hash_start_time = Instant::now();
    let key = argon2id_hash(raw_key, &header.salt, &header.header_type.version)?;
    let hash_duration = hash_start_time.elapsed();
    success!(
        "Successfully hashed your key [took {:.2}s]",
        hash_duration.as_secs_f32()
    );

    let decrypt_start_time = Instant::now();

    let ciphers = Ciphers::initialize(key, &header.header_type.algorithm)?;

    let payload = Payload {
        aad: &aad,
        msg: &encrypted_data,
    };

    let decrypted_bytes = ciphers.decrypt(&header.nonce, payload).map_err(|_| {
        anyhow::anyhow!(
            "Unable to decrypt the data. This means either: you're using the wrong key, this isn't an encrypted file, or the header has been tampered with."
        )
    })?;

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
        super::hashing::hash_stream(&[input.to_string()])?;
    }

    if params.erase != EraseMode::IgnoreFile(0) {
        super::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}

// this function is for decrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if the header says so (backwards-compat)
// it also manages using a detached header file if selected
// it creates the stream object and uses the convenience function provided by dexios-core
pub fn stream_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    let mut logger = Logger::new();

    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    let (header, aad) = match &params.header_location {
        HeaderLocation::Detached(contents) => {
            let mut header_file = File::open(contents)
                .with_context(|| format!("Unable to open header file: {}", input))?;
            let (header, aad) = header::Header::deserialize(&mut header_file)?;
            input_file
                .seek(std::io::SeekFrom::Start(header.get_size()))
                .context("Unable to seek input file")?;
            (header, aad)
        }
        HeaderLocation::Embedded => header::Header::deserialize(&mut input_file)?,
    };

    if header.header_type.mode == Mode::MemoryMode {
        drop(input_file);
        return memory_mode(input, output, params);
    }

    if !overwrite_check(output, params.skip)? {
        exit(0);
    }

    let raw_key = params.key.get_secret(&PasswordState::Direct)?;

    let mut output_file = File::create(output)?; // !!!attach context here

    logger.info(format!(
        "Using {} for decryption",
        header.header_type.algorithm
    ));

    logger.info(format!("Decrypting {} (this may take a while)", input));

    let key = match header.header_type.version {
        HeaderVersion::V1 | HeaderVersion::V2 | HeaderVersion::V3 => {
            let hash_start_time = Instant::now();
            let key = argon2id_hash(raw_key, &header.salt, &header.header_type.version)?;
            let hash_duration = hash_start_time.elapsed();
            success!(
                "Successfully hashed your key [took {:.2}s]",
                hash_duration.as_secs_f32()
            );
            key
        }
        HeaderVersion::V4 => {
            let hash_start_time = Instant::now();
            let keyslot = header.keyslots.clone().unwrap();

            let key = keyslot[0].hash_algorithm.hash(raw_key.clone(), &keyslot[0].salt)?;
            let hash_duration = hash_start_time.elapsed();
            success!(
                "Successfully hashed your key [took {:.2}s]",
                hash_duration.as_secs_f32()
            );
            let cipher = Ciphers::initialize(key, &header.header_type.algorithm)?;


            let master_key_result = cipher.decrypt(
                &keyslot[0].nonce,
                keyslot[0].encrypted_key.as_slice(),
            );
            let mut master_key_decrypted = master_key_result.map_err(|_| {
                anyhow::anyhow!(
                    "Unable to decrypt your master key (maybe you supplied the wrong key?)"
                )
            })?;

            let mut master_key = [0u8; 32];
            let len = 32.min(master_key_decrypted.len());
            master_key[..len].copy_from_slice(&master_key_decrypted[..len]);

            master_key_decrypted.zeroize();
            Protected::new(master_key)
        }
        HeaderVersion::V5 => {
            let keyslots = header.keyslots.clone().unwrap();
            let mut master_key = [0u8; 32];
            for keyslot in keyslots {
                let hash_start_time = Instant::now();
                let key = keyslot.hash_algorithm.hash(raw_key.clone(), &keyslot.salt)?;
                let hash_duration = hash_start_time.elapsed();
                success!(
                    "Successfully hashed your key [took {:.2}s]",
                    hash_duration.as_secs_f32()
                );
                let cipher = Ciphers::initialize(key, &header.header_type.algorithm)?;
        
                let master_key_result = cipher.decrypt(
                    &keyslot.nonce,
                    keyslot.encrypted_key.as_slice(),
                );

                if master_key_result.is_ok() {
                    let mut master_key_decrypted = master_key_result.unwrap();
        
                    let len = 32.min(master_key_decrypted.len());
                    master_key[..len].copy_from_slice(&master_key_decrypted[..len]);
                    master_key_decrypted.zeroize();
                    break;
                }
            }

            if master_key != [0u8; 32] {
                Protected::new(master_key)
            } else {
                return Err(anyhow::anyhow!("Unable to find a match with the key you provided (maybe you supplied the wrong key?)"))
            }
        }
    };

    let decrypt_start_time = Instant::now();

    let streams = DecryptionStreams::initialize(key, &header.nonce, &header.header_type.algorithm)?;

    streams.decrypt_file(&mut input_file, &mut output_file, &aad)?;

    let decrypt_duration = decrypt_start_time.elapsed();

    logger.success(format!(
        "Decryption successful! File saved as {} [took {:.2}s]",
        output,
        decrypt_duration.as_secs_f32(),
    ));

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[input.to_string()])?;
    }

    if params.erase != EraseMode::IgnoreFile(0) {
        super::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}
