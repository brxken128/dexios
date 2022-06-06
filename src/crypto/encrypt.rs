use crate::crypto::key::{argon2_hash, gen_salt};
use crate::crypto::streams::init_encryption_stream;
use crate::global::header::{Header, HeaderType};
use crate::global::secret::Secret;
use crate::global::states::{Algorithm, CipherMode};
use crate::global::{BLOCK_SIZE, VERSION};
use aead::Payload;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use paris::success;
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use std::fs::File;
use std::io::{Read, Write};
use std::result::Result::Ok;
use std::time::Instant;
use zeroize::Zeroize;

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

    let key = argon2_hash(raw_key, &salt, &header_type.header_version)?;

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

    let (mut streams, header) = init_encryption_stream(raw_key, header_type)?;

    header.write(output)?; // !!!attach context


    let aad = header.serialize()?;

    let mut read_buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();

    loop {
        let read_count = input
            .read(&mut read_buffer)
            .context("Unable to read from the input file")?;
        if read_count == BLOCK_SIZE {
            // aad is just empty bytes normally
            // create_aad returns empty bytes if the header isn't V3+
            // this means we don't need to do anything special in regards to older versions
            let payload = Payload {
                aad: &aad,
                msg: read_buffer.as_ref(),
            };

            let encrypted_data = match streams.encrypt_next(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to encrypt the data")),
            };

            output
                .write_all(&encrypted_data)
                .context("Unable to write to the output file")?;
        } else {
            // if we read something less than BLOCK_SIZE, and have hit the end of the file
            let payload = Payload {
                aad: &aad,
                msg: &read_buffer[..read_count],
            };

            let encrypted_data = match streams.encrypt_last(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to encrypt the data")),
            };

            output
                .write_all(&encrypted_data)
                .context("Unable to write to the output file")?;
            break;
        }
    }

    read_buffer.zeroize();

    output.flush().context("Unable to flush the output file")?;
    Ok(())
}
