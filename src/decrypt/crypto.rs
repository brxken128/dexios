use crate::global::enums::{Algorithm, BenchMode, HashMode, OutputFile};
use crate::global::structs::Header;
use crate::global::BLOCK_SIZE;
use crate::header::get_aad;
use crate::key::argon2_hash;
use crate::secret::Secret;
use crate::streams::init_decryption_stream;
use aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use blake3::Hasher;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use deoxys::DeoxysII256;
use paris::success;
use std::fs::File;
use std::io::Read;
use std::result::Result::Ok;
use std::time::Instant;

// this decrypts the data in memory mode
// it takes the data, a Secret<> key, the salt and the 12 byte nonce
// most of the information for decryption is stored within the header
// it hashes the key with the supplised salt, and decrypts all of the data
// it returns the decrypted bytes
pub fn decrypt_bytes_memory_mode(
    header: &Header,
    data: &[u8],
    output: &mut OutputFile,
    raw_key: Secret<Vec<u8>>,
    bench: BenchMode,
    hash: HashMode,
) -> Result<()> {
    let key = argon2_hash(raw_key, &header.salt, &header.header_type.header_version)?;

    let aad = get_aad(header)?;
    let payload = Payload { aad: &aad, msg: data };

    let decrypted_bytes = match header.header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce = Nonce::from_slice(&header.nonce);
            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            match cipher.decrypt(nonce, payload) {
                Ok(decrypted_bytes) => decrypted_bytes,
                Err(_) => return Err(anyhow!("Unable to decrypt the data. Maybe it's the wrong key, or it's not an encrypted file."))
            }
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce = XNonce::from_slice(&header.nonce);
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            match cipher.decrypt(nonce, payload) {
                Ok(decrypted_bytes) => decrypted_bytes,
                Err(_) => return Err(anyhow!("Unable to decrypt the data. Maybe it's the wrong key, or it's not an encrypted file."))
            }
        }
        Algorithm::DeoxysII256 => {
            let nonce = deoxys::Nonce::from_slice(&header.nonce);
            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            match cipher.decrypt(nonce, payload) {
                Ok(decrypted_bytes) => decrypted_bytes,
                Err(_) => return Err(anyhow!("Unable to decrypt the data. Maybe it's the wrong key, or it's not an encrypted file."))
            }
        }
    };

    let mut hasher = Hasher::new();

    if hash == HashMode::CalculateHash {
        let hash_start_time = Instant::now();
        crate::header::hash(&mut hasher, header);
        hasher.update(data);
        let hash = hasher.finalize().to_hex().to_string();
        let hash_duration = hash_start_time.elapsed();
        success!(
            "Hash of the encrypted file is: {} [took {:.2}s]",
            hash,
            hash_duration.as_secs_f32()
        );
    }

    if bench == BenchMode::WriteToFilesystem {
        let write_start_time = Instant::now();
        output.write_all(&decrypted_bytes)?;
        let write_duration = write_start_time.elapsed();
        success!("Wrote to file [took {:.2}s]", write_duration.as_secs_f32());
    }

    Ok(())
}

// this decrypts data in stream mode
// it takes an input file handle, an output file handle, a Secret<> raw key, and enums with specific modes
// most of the information for decryption is stored within the header
// it gets the streams enum from `init_decryption_stream`
// it creates the encryption cipher and then reads the file in blocks (including the gcm tag)
// on each read, it decrypts, writes (if enabled), hashes (if enabled) and repeats until EOF
pub fn decrypt_bytes_stream_mode(
    input: &mut File,
    output: &mut OutputFile,
    raw_key: Secret<Vec<u8>>,
    header: &Header,
    bench: BenchMode,
    hash: HashMode,
) -> Result<()> {
    let mut hasher = blake3::Hasher::new();

    let mut streams = init_decryption_stream(raw_key, header)?;

    if hash == HashMode::CalculateHash {
        crate::header::hash(&mut hasher, header);
    }

    let aad = get_aad(header)?;

    let mut buffer = vec![0u8; BLOCK_SIZE + 16].into_boxed_slice();

    loop {
        let read_count = input.read(&mut buffer)?;
        if read_count == (BLOCK_SIZE + 16) {
            let payload = Payload { aad: &aad, msg: buffer.as_ref() };

            let decrypted_data = match streams.decrypt_next(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to decrypt the data. Maybe it's the wrong key, or it's not an encrypted file.")),
            };

            if bench == BenchMode::WriteToFilesystem {
                output
                    .write_all(&decrypted_data)
                    .context("Unable to write to the output file")?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&buffer);
            }
        } else {
            // if we read something less than BLOCK_SIZE+16, and have hit the end of the file
            let payload = Payload { aad: &aad, msg: &buffer[..read_count] };


            let decrypted_data = match streams.decrypt_last(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to decrypt the final block of data. Maybe it's the wrong key, or it's not an encrypted file.")),
            };

            if bench == BenchMode::WriteToFilesystem {
                output
                    .write_all(&decrypted_data)
                    .context("Unable to write to the output file")?;
                output.flush().context("Unable to flush the output file")?;
            }
            if hash == HashMode::CalculateHash {
                hasher.update(&buffer[..read_count]);
            }
            break;
        }
    }

    if hash == HashMode::CalculateHash {
        let hash = hasher.finalize().to_hex().to_string();
        success!("Hash of the encrypted file is: {}. If this doesn't match with the original, something very bad has happened.", hash);
    }

    Ok(())
}
