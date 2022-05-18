use std::fs::File;

use crate::global::{DexiosFile, BLOCK_SIZE, SALT_LEN};
use aes_gcm::aead::{stream::EncryptorLE31, Aead, NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use anyhow::Result;
use anyhow::{Context, Ok};
use argon2::Argon2;
use argon2::Params;
use rand::{prelude::StdRng, Rng, RngCore, SeedableRng};
use secrecy::{ExposeSecret, Secret};
use std::io::Read;
use std::io::Write;

fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt: [u8; SALT_LEN] = [0; SALT_LEN];
    StdRng::from_entropy().fill_bytes(&mut salt);
    salt
}

fn gen_key(raw_key: Secret<Vec<u8>>) -> Result<(Secret<[u8; 32]>, [u8; SALT_LEN])> {
    let mut key = [0u8; 32];
    let salt = gen_salt();

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::default(),
    );
    let result = argon2.hash_password_into(raw_key.expose_secret(), &salt, &mut key);

    if result.is_err() {
        return Err(anyhow!("Error while hashing your password with argon2id"));
    }

    Ok((Secret::new(key), salt))
}

fn gen_nonce() -> [u8; 12] {
    StdRng::from_entropy().gen::<[u8; 12]>()
}

pub fn encrypt_bytes(data: Vec<u8>, raw_key: Secret<Vec<u8>>) -> Result<DexiosFile> {
    let nonce_bytes = gen_nonce();
    let nonce = Nonce::from_slice(nonce_bytes.as_slice());

    let (key, salt) = gen_key(raw_key)?;
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret());
    
    if cipher.is_err() {
        return Err(anyhow!("Unable to create cipher with argon2id hashed key."))
    }

    let cipher = cipher.unwrap();
    let encrypted_bytes = cipher.encrypt(nonce, data.as_slice());

    if encrypted_bytes.is_err() {
        return Err(anyhow!("Unable to encrypt the data"));
    }

    drop(data);

    Ok(DexiosFile {
        salt,
        nonce: nonce_bytes,
        data: encrypted_bytes.unwrap(),
    })
}

pub fn encrypt_bytes_stream(
    input: &mut File,
    output: &mut File,
    raw_key: Secret<Vec<u8>>,
    bench: bool,
    hash: bool,
) -> Result<()> {
    let nonce_bytes = StdRng::from_entropy().gen::<[u8; 8]>();
    let nonce = Nonce::from_slice(&nonce_bytes); // truncate to correct size

    let (key, salt) = gen_key(raw_key)?;
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret());
    
    if cipher.is_err() {
        return Err(anyhow!("Unable to create cipher with argon2id hashed key."))
    }

    let cipher = cipher.unwrap();

    let mut stream = EncryptorLE31::from_aead(cipher, nonce);

    if !bench {
        output
            .write_all(&salt)
            .context("Unable to write salt to the output file")?;
        output
            .write_all(&nonce_bytes)
            .context("Unable to write nonce to the output file")?;
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(&salt);
    hasher.update(&nonce_bytes);

    let mut buffer = [0u8; BLOCK_SIZE];

    loop {
        let read_count = input
            .read(&mut buffer)
            .context("Unable to read from the input file")?;
        if read_count == BLOCK_SIZE {
            // buffer length
            let encrypted_data = stream.encrypt_next(buffer.as_slice());

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
            let encrypted_data = stream.encrypt_last(&buffer[..read_count]);

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
