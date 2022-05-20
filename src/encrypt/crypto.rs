use std::fs::File;

use crate::global::{BLOCK_SIZE, SALT_LEN, CipherType, EncryptStreamCiphers};
use aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use anyhow::Result;
use anyhow::{Context, Ok};
use argon2::Argon2;
use argon2::Params;
use chacha20poly1305::XChaCha20Poly1305;
use rand::{prelude::StdRng, Rng, RngCore, SeedableRng};
use secrecy::{ExposeSecret, Secret};
use std::io::Read;
use std::io::Write;

// this generates a salt for password hashing
fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt: [u8; SALT_LEN] = [0; SALT_LEN];
    StdRng::from_entropy().fill_bytes(&mut salt);
    salt
}

// this handles argon2 hashing with the provided key
// it returns the key and a salt
fn gen_key(raw_key: Secret<Vec<u8>>) -> Result<(Secret<[u8; 32]>, [u8; SALT_LEN])> {
    let mut key = [0u8; 32];
    let salt = gen_salt();

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

    Ok((Secret::new(key), salt))
}

fn gen_nonce() -> [u8; 12] {
    StdRng::from_entropy().gen::<[u8; 12]>()
}

// this encrypts data in memory mode
// it takes the data and a Secret<> key
// it generates the 12 byte nonce, hashes the key and encrypts the data
// it returns the salt, nonce, and encrypted bytes
pub fn encrypt_bytes_memory_mode(
    data: Secret<Vec<u8>>,
    raw_key: Secret<Vec<u8>>,
) -> Result<([u8; SALT_LEN], [u8; 12], Vec<u8>)> {
    let nonce_bytes = gen_nonce();
    let nonce = Nonce::from_slice(nonce_bytes.as_slice());

    let (key, salt) = gen_key(raw_key)?;
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret());
    drop(key);

    if cipher.is_err() {
        return Err(anyhow!("Unable to create cipher with argon2id hashed key."));
    }

    let cipher = cipher.unwrap();

    let encrypted_bytes = cipher.encrypt(nonce, data.expose_secret().as_slice());

    if encrypted_bytes.is_err() {
        return Err(anyhow!("Unable to encrypt the data"));
    }

    drop(data);

    Ok((salt, nonce_bytes, encrypted_bytes.unwrap()))
}

// this encrypts data in stream mode
// it takes an input file handle, an output file handle, a Secret<> key, and bools for if we're in bench/hash mode
// it generates the 8 byte nonce, creates the encryption cipher and then reads the file in blocks
// on each read, it encrypts, writes (if enabled), hashes (if enabled) and repeats until EOF
// this could probably do with some delegation - it does a lot of stuff on it's own
pub fn encrypt_bytes_stream_mode(
    input: &mut File,
    output: &mut File,
    raw_key: Secret<Vec<u8>>,
    bench: bool,
    hash: bool,
    cipher_type: CipherType,
) -> Result<()> {
    let (mut streams, salt, nonce_bytes): (EncryptStreamCiphers, [u8; SALT_LEN], Vec<u8>) = match cipher_type {
        CipherType::AesGcm => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 8]>();
            let nonce = Nonce::from_slice(&nonce_bytes);
        
            let (key, salt) = gen_key(raw_key)?;
            let cipher = Aes256Gcm::new_from_slice(key.expose_secret());
            drop(key);

            if cipher.is_err() {
                return Err(anyhow!("Unable to create cipher with argon2id hashed key."));
            }
        
            let cipher = cipher.unwrap();
        
            let stream = aes_gcm::aead::stream::EncryptorLE31::from_aead(cipher, nonce);
            (EncryptStreamCiphers::AesGcm(stream), salt, nonce_bytes.to_vec())
        },
        CipherType::XChaCha20Poly1305 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 20]>();

            let (key, salt) = gen_key(raw_key)?;
            let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret());
            drop(key);
        
            if cipher.is_err() {
                return Err(anyhow!("Unable to create cipher with argon2id hashed key."));
            }
        
            let cipher = cipher.unwrap();
        
            let stream = chacha20poly1305::aead::stream::EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            (EncryptStreamCiphers::XChaCha(stream), salt, nonce_bytes.to_vec())
        }
    };

    if !bench {
        output
            .write_all(&salt)
            .context("Unable to write salt to the output file")?;
        output
            .write_all(&nonce_bytes)
            .context("Unable to write nonce to the output file")?;
    }

    let mut hasher = blake3::Hasher::new();

    if hash {
        hasher.update(&salt);
        hasher.update(&nonce_bytes);
    }

    let mut buffer = [0u8; BLOCK_SIZE];

    loop {
        let read_count = input
            .read(&mut buffer)
            .context("Unable to read from the input file")?;
        if read_count == BLOCK_SIZE {
            // buffer length
            let encrypted_data = streams.encrypt_next(buffer.as_slice());

            if encrypted_data.is_err() {
                return Err(anyhow!("Unable to encrypt the data"));
            }

            let encrypted_data = encrypted_data.unwrap();
            if !bench {
                output
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output file")?;
            }
            if hash {
                hasher.update(&encrypted_data);
            }
        } else {
            // if we read something less than BLOCK_SIZE, and have hit the end of the file
            let encrypted_data = streams.encrypt_last(&buffer[..read_count]);

            if encrypted_data.is_err() {
                return Err(anyhow!("Unable to encrypt the final block of data"));
            }

            let encrypted_data = encrypted_data.unwrap();
            if !bench {
                output
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output file")?;
            }
            if hash {
                hasher.update(&encrypted_data);
            }
            break;
        }
    }
    if !bench {
        output.flush().context("Unable to flush the output file")?;
    }
    if hash {
        let hash = hasher.finalize().to_hex().to_string();
        println!("Hash of the encrypted file is: {}", hash,);
    }
    Ok(())
}