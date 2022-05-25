use crate::global::crypto::DecryptStreamCiphers;
use crate::global::parameters::{BenchMode, Algorithm, HashMode, OutputFile, HeaderType, CipherMode};
use crate::global::{BLOCK_SIZE, SALT_LEN, VERSION};
use crate::key::hash_key;
use aead::stream::DecryptorLE31;
use aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, Secret};
use std::fs::File;
use std::io::Read;
use std::result::Result::Ok;

// this decrypts the data in memory mode
// it takes the data, a Secret<> key, the salt and the 12 byte nonce
// it hashes the key with the supplised salt, and decrypts all of the data
// it returns the decrypted bytes
pub fn decrypt_bytes_memory_mode(
    salt: [u8; 16],
    nonce: &[u8],
    data: &[u8],
    raw_key: Secret<Vec<u8>>,
    algorithm: Algorithm,
) -> Result<Vec<u8>> {
    let key = hash_key(raw_key, &salt)?;

    return match algorithm {
        Algorithm::AesGcm => {
            let nonce = Nonce::from_slice(nonce);
            let cipher = match Aes256Gcm::new_from_slice(key.expose_secret()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            match cipher.decrypt(nonce, data) {
                Ok(decrypted_bytes) => Ok(decrypted_bytes),
                Err(_) => Err(anyhow!("Unable to decrypt the data. Maybe it's the wrong key, or it's not an encrypted file."))
            }
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce = XNonce::from_slice(nonce);
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose_secret()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            match cipher.decrypt(nonce, data) {
                Ok(decrypted_bytes) => Ok(decrypted_bytes),
                Err(_) => Err(anyhow!("Unable to decrypt the data. Maybe it's the wrong key, or it's not an encrypted file."))
            }
        }
    };
}

// this decrypts data in stream mode
// it takes an input file handle, an output file handle, a Secret<> key, and bools for if we're in bench/hash mode
// it reads the salt and the 8 byte nonce, creates the encryption cipher and then reads the file in blocks (including the gcm tag)
// on each read, it decrypts, writes (if enabled), hashes (if enabled) and repeats until EOF
// this could probably do with some delegation - it does a lot of stuff on it's own
pub fn decrypt_bytes_stream_mode(
    input: &mut File,
    output: &mut OutputFile,
    raw_key: Secret<Vec<u8>>,
    bench: BenchMode,
    hash: HashMode,
) -> Result<()> {
    // let mut salt = [0u8; SALT_LEN];
    // input
    //     .read(&mut salt)
    //     .context("Unable to read salt from the file")?;

    let header = crate::header::read_from_file(input)?;

    let mut hasher = blake3::Hasher::new();

    // if hash == HashMode::CalculateHash {
    //     hasher.update(&salt);
    // }

    // let key = hash_key(raw_key, &salt)?;
    let key = hash_key(raw_key, &header.salt)?;

    let mut streams: DecryptStreamCiphers = match header.header_type.algorithm {
        Algorithm::AesGcm => {
            let cipher = match Aes256Gcm::new_from_slice(key.expose_secret()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };


            let nonce = Nonce::from_slice(header.nonce.as_slice());

            let stream = DecryptorLE31::from_aead(cipher, nonce);

            DecryptStreamCiphers::AesGcm(Box::new(stream))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose_secret()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            DecryptStreamCiphers::XChaCha(Box::new(stream))
        }
    };

    if hash == HashMode::CalculateHash {
        crate::header::hash(&mut hasher, &header.salt, &header.nonce, &header.header_type);
    }

    let mut buffer = [0u8; BLOCK_SIZE + 16]; // 16 bytes is the length of the AEAD tag

    loop {
        let read_count = input.read(&mut buffer)?;
        if read_count == (BLOCK_SIZE + 16) {
            let decrypted_data = match streams.decrypt_next(buffer.as_slice()) {
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
            let decrypted_data = match streams.decrypt_last(&buffer[..read_count]) {
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
        println!("Hash of the encrypted file is: {}. If this doesn't match with the original, something very bad has happened.", hash);
    }

    Ok(())
}
