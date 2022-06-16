use super::key::get_secret;
use super::prompt::overwrite_check;
use crate::global::states::EraseMode;
use crate::global::states::HashMode;
use crate::global::structs::CryptoParams;
use anyhow::Context;
use anyhow::{Ok, Result};
use dexios_core::cipher::Ciphers;
use dexios_core::header::{Header, HeaderType, HEADER_VERSION};
use dexios_core::key::{balloon_hash, gen_salt};
use dexios_core::primitives::gen_nonce;
use dexios_core::primitives::Algorithm;
use dexios_core::primitives::Mode;
use dexios_core::protected::Protected;
use paris::Logger;
use rand::RngCore;
use rand::SeedableRng;
use rand::prelude::StdRng;
use std::fs::File;
use std::io::Write;
use std::process::exit;
use std::time::Instant;

use dexios_core::stream::EncryptionStreams;

// this function is for encrypting a file in stream mode
// it handles any user-facing interactiveness, opening files
// it creates the stream object and uses the convenience function provided by dexios-core
pub fn stream_mode(
    input: &str,
    output: &str,
    params: &CryptoParams,
    algorithm: Algorithm,
) -> Result<()> {
    let mut logger = Logger::new();

    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {}", input))?;

    if !overwrite_check(output, params.skip)? {
        exit(0);
    }

    let raw_key = get_secret(&params.keyfile, true, params.password)?;

    let mut output_file = File::create(output)?; // !!!attach context

    logger.info(format!("Using {} for encryption", algorithm));
    logger.info(format!("Encrypting {} (this may take a while)", input));

    let header_type = HeaderType {
        version: HEADER_VERSION,
        mode: Mode::StreamMode,
        algorithm,
    };

    let salt = gen_salt();
    let hash_start_time = Instant::now();
    let key = balloon_hash(raw_key, &salt, &header_type.version)?;
    let hash_duration = hash_start_time.elapsed();
    logger.success(format!(
        "Successfully hashed your key [took {:.2}s]",
        hash_duration.as_secs_f32()
    ));

    let encrypt_start_time = Instant::now();

    let mut master_key = [0u8; 32];
    StdRng::from_entropy().fill_bytes(&mut master_key);

    let master_key = Protected::new(master_key);

    let master_key_nonce = gen_nonce(&header_type.algorithm, &Mode::MemoryMode);
    let cipher = Ciphers::initialize(key, &header_type.algorithm)?;
    let master_key_result = cipher.encrypt(&master_key_nonce, master_key.expose().as_slice());

    let master_key_encrypted = match master_key_result {
        std::result::Result::Ok(bytes) => bytes,
        Err(_) => return Err(anyhow::anyhow!("Unable to encrypt your master key"))
    };

    let nonce = gen_nonce(&header_type.algorithm, &header_type.mode);
    let streams = EncryptionStreams::initialize(master_key, &nonce, &header_type.algorithm)?;

    let header = Header {
        header_type,
        nonce,
        salt,
        master_key_encrypted: Some(master_key_encrypted),
        master_key_nonce: Some(master_key_nonce),
    };

    header.write(&mut output_file)?;

    let aad = header.serialize()?;

    streams.encrypt_file(&mut input_file, &mut output_file, &aad)?;

    output_file
        .flush()
        .context("Unable to flush the output file")?;

    let encrypt_duration = encrypt_start_time.elapsed();

    logger.success(format!(
        "Encryption successful! File saved as {} [took {:.2}s]",
        output,
        encrypt_duration.as_secs_f32(),
    ));

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&vec![output.to_string()])?;
    }

    if params.erase != EraseMode::IgnoreFile(0) {
        super::erase::secure_erase(input, params.erase.get_passes())?;
    }

    Ok(())
}
