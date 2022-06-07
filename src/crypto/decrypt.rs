use crate::crypto::key::argon2_hash;
use crate::crypto::primitives::cipher::Ciphers;
use crate::global::header::Header;
use crate::global::protected::Protected;
use aead::Payload;
use anyhow::anyhow;
use anyhow::Result;
use paris::success;
use std::fs::File;
use std::io::Write;
use std::result::Result::Ok;
use std::time::Instant;

use super::primitives::stream::DecryptStreamCiphers;

// this decrypts the data in memory mode
// it takes the data, a Protected<> key, the salt and the 12 byte nonce
// most of the information for decryption is stored within the header
// it hashes the key with the supplised salt, and decrypts all of the data
// it returns the decrypted bytes
// this is only here for backwards-compatibility
pub fn memory_mode(
    header: &Header,
    data: &[u8],
    output: &mut File,
    raw_key: Protected<Vec<u8>>,
    aad: &[u8],
) -> Result<()> {
    let key = argon2_hash(raw_key, header.salt, &header.header_type.header_version)?;

    let ciphers = Ciphers::initialize(key, header.header_type.algorithm)?;

    let payload = Payload { aad, msg: data };

    let decrypted_bytes = match ciphers.decrypt(&header.nonce, payload) {
        Ok(decrypted_bytes) => decrypted_bytes,
        Err(_) => {
            return Err(anyhow!(
            "Unable to decrypt the data. This means either: you're using the wrong key, this isn't an encrypted file, or the header has been tampered with."
        ))
        }
    };

    let write_start_time = Instant::now();
    output.write_all(&decrypted_bytes)?;
    let write_duration = write_start_time.elapsed();
    success!("Wrote to file [took {:.2}s]", write_duration.as_secs_f32());

    Ok(())
}

// this decrypts data in stream mode
// it takes an input file handle, an output file handle, a Protected<> raw key, and enums with specific modes
// most of the information for decryption is stored within the header
// it gets the streams enum from `init_decryption_stream`
// it creates the encryption cipher and then reads the file in blocks (including the gcm tag)
// on each read, it decrypts, writes (if enabled), hashes (if enabled) and repeats until EOF
// pub fn stream_mode(
//     input: &mut File,
//     output: &mut File,
//     raw_key: Protected<Vec<u8>>,
//     header: &Header,
//     aad: &[u8],
// ) -> Result<()> {


//     Ok(())
// }
