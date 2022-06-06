use crate::crypto::key::{argon2_hash, gen_salt};
use crate::crypto::streams::init_encryption_stream;
use crate::global::header::{Header, HeaderType};
use crate::global::secret::Secret;
use crate::global::states::{Algorithm, CipherMode};
use crate::global::VERSION;
use aead::Payload;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use paris::success;
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use std::fs::File;
use std::io::Write;
use std::result::Result::Ok;
use std::time::Instant;

use super::memory::init_memory_cipher;

// this encrypts data in memory mode
// it takes the data and a Secret<> key
// it generates the nonce, hashes the key and encrypts the data
// it writes the header and then the encrypted data to the output file
#[allow(clippy::too_many_lines)]
// !!! delegate the `match algorithm` to a file like `memory.rs`
// similar to stream initialisation
pub fn memory_mode(
    data: Secret<Vec<u8>>,
    output: &mut File,
    raw_key: Secret<Vec<u8>>,
    algorithm: Algorithm,
) -> Result<()> {
    let salt = gen_salt();

    let header_type = HeaderType {
        header_version: VERSION,
        cipher_mode: CipherMode::MemoryMode,
        algorithm,
    };

    let key = argon2_hash(raw_key, salt, &header_type.header_version)?;

    // let nonce_bytes = StdRng::from_entropy().gen::<[u8; 12]>();

    let nonce = match header_type.algorithm {
        Algorithm::Aes256Gcm => StdRng::from_entropy().gen::<[u8; 12]>().to_vec(),
        Algorithm::XChaCha20Poly1305 => StdRng::from_entropy().gen::<[u8; 24]>().to_vec(),
        Algorithm::DeoxysII256 => StdRng::from_entropy().gen::<[u8; 15]>().to_vec(),
    };

    let ciphers = init_memory_cipher(key, algorithm)?;

    let header = Header {
        header_type,
        nonce,
        salt,
    };

    let aad = header.serialize()?;

    let payload = Payload {
        aad: &aad,
        msg: data.expose().as_slice(),
    };

    let encrypted_bytes = match ciphers.encrypt(&header.nonce, payload) {
        Ok(bytes) => bytes,
        Err(_) => return Err(anyhow!("Unable to encrypt the data")),
    };

    drop(data);

    let write_start_time = Instant::now();
    header.write(output)?; // !!!attach context
    output.write_all(&encrypted_bytes)?;
    let write_duration = write_start_time.elapsed();
    success!("Wrote to file [took {:.2}s]", write_duration.as_secs_f32());

    Ok(())
}

// this encrypts data in stream mode
// it takes an input file handle, an output file handle, a Secret<> key, and enums for specific modes
// it gets the nonce, salt and streams enum from `init_encryption_stream` and then reads the file in blocks
// on each read, it encrypts, writes (if enabled), hashes (if enabled) and repeats until EOF
// it also handles the prep of each individual stream, via the match statement
pub fn stream_mode(
    input: &mut File,
    output: &mut File,
    raw_key: Secret<Vec<u8>>,
    algorithm: Algorithm,
) -> Result<()> {
    let header_type = HeaderType {
        header_version: VERSION,
        cipher_mode: CipherMode::StreamMode,
        algorithm,
    };

    let salt = gen_salt();
    let key = argon2_hash(raw_key, salt, &header_type.header_version)?;

    let (streams, nonce) = init_encryption_stream(key, header_type.algorithm)?;

    let header = Header {
        header_type,
        nonce,
        salt,
    };

    header.write(output)?;

    let aad = header.serialize()?;

    streams.encrypt_file(input, output, &aad)?;

    output.flush().context("Unable to flush the output file")?;
    Ok(())
}
