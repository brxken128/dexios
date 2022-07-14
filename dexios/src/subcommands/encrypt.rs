use super::prompt::overwrite_check;
use crate::global::states::EraseMode;
use crate::global::states::HashMode;
use crate::global::states::HeaderLocation;
use crate::global::states::PasswordState;
use crate::global::structs::CryptoParams;
use anyhow::Context;
use anyhow::Result;
use dexios_core::cipher::Ciphers;
use dexios_core::header::HashingAlgorithm;
use dexios_core::header::Keyslot;
use dexios_core::header::{Header, HeaderType, HEADER_VERSION};
use dexios_core::key::gen_salt;
use dexios_core::primitives::gen_nonce;
use dexios_core::primitives::Algorithm;
use dexios_core::primitives::Mode;
use dexios_core::protected::Protected;
use paris::Logger;
use rand::prelude::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use std::fs::File;
use std::io::Seek;
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

    let raw_key = params.key.get_secret(&PasswordState::Validate)?;

    let mut output_file = File::create(output)?; // !!!attach context

    logger.info(format!("Using {} for encryption", algorithm));
    logger.info(format!("Encrypting {} (this may take a while)", input));

    let header_type = HeaderType {
        version: HEADER_VERSION,
        mode: Mode::StreamMode,
        algorithm,
    };

    let salt = gen_salt();

    let hash_algorithm = HashingAlgorithm::Blake3Balloon(5);

    let hash_start_time = Instant::now();
    let key = hash_algorithm.hash(raw_key, &salt)?;
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

    let master_key_encrypted =
        master_key_result.map_err(|_| anyhow::anyhow!("Unable to encrypt your master key"))?;

    let mut master_key_encrypted_array = [0u8; 48];

    let len = 48.min(master_key_encrypted.len());
    master_key_encrypted_array[..len].copy_from_slice(&master_key_encrypted[..len]);

    let keyslot = Keyslot {
        encrypted_key: master_key_encrypted_array,
        hash_algorithm,
        nonce: master_key_nonce,
        salt,
    };

    let keyslots = vec![keyslot];

    let nonce = gen_nonce(&header_type.algorithm, &header_type.mode);
    let streams = EncryptionStreams::initialize(master_key, &nonce, &header_type.algorithm)?;

    let header = Header {
        header_type,
        nonce,
        salt: None, // legacy, this is now supplied in keyslots
        keyslots: Some(keyslots),
    };

    match &params.header_location {
        HeaderLocation::Embedded => {
            header.write(&mut output_file)?;
        }
        HeaderLocation::Detached(path) => {
            if !overwrite_check(path, params.skip)? {
                exit(0);
            }

            let mut header_file =
                File::create(path).context("Unable to create file for the header")?;

            header
                .write(&mut header_file)
                .context("Unable to write header to the file")?;

            let header_size = header
                .get_size()
                .try_into()
                .context("Unable to get header size as i64")?;
            output_file.seek(std::io::SeekFrom::Current(header_size))?;
        }
    }

    let aad = header.create_aad()?;

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
        super::hashing::hash_stream(&[output.to_string()])?;
    }

    if let EraseMode::EraseFile(passes) = params.erase {
        super::erase::secure_erase(input, passes)?;
    }

    Ok(())
}
