use std::fs::File;

use crate::global::{BLOCK_SIZE, SALT_LEN, CipherType, DecryptStreamCiphers};
use aead::stream::DecryptorLE31;
use aead::{Aead, NewAead};
use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Ok;
use argon2::Argon2;
use argon2::Params;
use secrecy::{ExposeSecret, Secret};
use std::io::Read;
use std::io::Write;

// this handles argon2id hashing with the provided key and salt
fn get_key(raw_key: Secret<Vec<u8>>, salt: [u8; SALT_LEN]) -> Result<Secret<[u8; 32]>> {
    let mut key = [0u8; 32];

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::default(),
    );
    let result = argon2.hash_password_into(raw_key.expose_secret(), &salt, &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(anyhow!("Error while hashing your password with argon2id"));
    }

    Ok(Secret::new(key))
}

// this decrypts the data in memory mode
// it takes the data, a Secret<> key, the salt and the 12 byte nonce
// it hashes the key with the supplised salt, and decrypts all of the data
// it returns the decrypted bytes
pub fn decrypt_bytes_memory_mode(
    salt: [u8; 16],
    nonce: [u8; 12],
    data: &[u8],
    raw_key: Secret<Vec<u8>>,
) -> Result<Vec<u8>> {
    let key = get_key(raw_key, salt)?;

    let nonce = Nonce::from_slice(nonce.as_slice());
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret());
    drop(key);

    if cipher.is_err() {
        return Err(anyhow!("Unable to create cipher with argon2id hashed key."));
    }

    let cipher = cipher.unwrap();

    let decrypted_bytes = cipher.decrypt(nonce, data);

    if decrypted_bytes.is_err() {
        return Err(anyhow!(
            "Unable to decrypt the data. Maybe it's the wrong key, or it's not an encrypted file."
        ));
    }

    Ok(decrypted_bytes.unwrap())
}

// this decrypts data in stream mode
// it takes an input file handle, an output file handle, a Secret<> key, and bools for if we're in bench/hash mode
// it reads the salt and the 8 byte nonce, creates the encryption cipher and then reads the file in blocks (including the gcm tag)
// on each read, it decrypts, writes (if enabled), hashes (if enabled) and repeats until EOF
// this could probably do with some delegation - it does a lot of stuff on it's own
pub fn decrypt_bytes_stream_mode(
    input: &mut File,
    output: &mut File,
    raw_key: Secret<Vec<u8>>,
    bench: bool,
    hash: bool,
    cipher_type: CipherType,
) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    let key = get_key(raw_key, salt)?;
    input
        .read(&mut salt)
        .context("Unable to read salt from the file")?;

    let mut hasher = blake3::Hasher::new();

    if hash {
        hasher.update(&salt);
    }

    let mut streams: DecryptStreamCiphers = match cipher_type {
        CipherType::AesGcm => {
            let mut nonce_bytes = [0u8; 8];
            input
                .read(&mut nonce_bytes)
                .context("Unable to read nonce from the file")?;
        
            if hash {
                hasher.update(&nonce_bytes);
            }

            let nonce = Nonce::from_slice(nonce_bytes.as_slice());
            let cipher = Aes256Gcm::new_from_slice(key.expose_secret());
            drop(key);

            if cipher.is_err() {
                return Err(anyhow!("Unable to create cipher with argon2id hashed key."));
            }
        
            let cipher = cipher.unwrap();
        
            let stream = DecryptorLE31::from_aead(cipher, nonce);

            DecryptStreamCiphers::AesGcm(stream)
        },
        CipherType::XChaCha20Poly1305 => {
            let mut nonce_bytes = [0u8; 20];
            input
                .read(&mut nonce_bytes)
                .context("Unable to read nonce from the file")?;

            if hash {
                hasher.update(&nonce_bytes);
            }

            let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret());
            drop(key);

            if cipher.is_err() {
                return Err(anyhow!("Unable to create cipher with argon2id hashed key."));
            }
        
            let cipher = cipher.unwrap();
        
            let stream = DecryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            DecryptStreamCiphers::XChaCha(stream)
        }
    };


    let mut buffer = [0u8; BLOCK_SIZE + 16]; // 16 bytes is the length of the AEAD tag

    loop {
        let read_count = input.read(&mut buffer)?;
        if read_count == (BLOCK_SIZE + 16) {
            let decrypted_data = streams.decrypt_next(buffer.as_slice());

            if decrypted_data.is_err() {
                return Err(anyhow!("Unable to decrypt the data. Maybe it's the wrong key, or it's not an encrypted file."));
            }

            let decrypted_data = decrypted_data.unwrap();
            if !bench {
                output
                    .write_all(&decrypted_data)
                    .context("Unable to write to the output file")?;
            }
            if hash {
                hasher.update(&buffer);
            }
        } else {
            // if we read something less than BLOCK_SIZE+16, and have hit the end of the file
            // let decrypted_data = stream.decrypt_last(&buffer[..read_count]);

            let decrypted_data = streams.decrypt_last(&buffer[..read_count]);

            if decrypted_data.is_err() {
                return Err(anyhow!("Unable to decrypt the final block of data. Maybe it's the wrong key, or it's not an encrypted file."));
            }

            let decrypted_data = decrypted_data.unwrap();
            if !bench {
                output
                    .write_all(&decrypted_data)
                    .context("Unable to write to the output file")?;
                output.flush().context("Unable to flush the output file")?;
            }
            if hash {
                hasher.update(&buffer[..read_count]);
            }
            break;
        }
    }

    if hash {
        let hash = hasher.finalize().to_hex().to_string();
        println!("Hash of the encrypted file is: {}. If this doesn't match with the original, something very bad has happened.", hash);
    }

    Ok(())
}