use crate::crypto::key::{argon2_hash, gen_salt};
use crate::global::header::{Header, HeaderType};
use crate::global::secret::Secret;
use crate::global::states::{Algorithm, CipherMode};
use crate::global::VERSION;
use anyhow::Context;
use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::result::Result::Ok;

use super::primitives::stream::EncryptStreamCiphers;

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

    let (streams, nonce) = EncryptStreamCiphers::initialize(key, header_type.algorithm)?;

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
