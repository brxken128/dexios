use std::fs::File;

use crate::global::{BLOCK_SIZE, SALT_LEN};
use aes_gcm::aead::stream::DecryptorLE31;
use anyhow::Result;

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Ok;
use argon2::Argon2;
use argon2::Params;
use secrecy::{ExposeSecret, Secret};
use std::io::Read;
use std::io::Write;

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

pub fn decrypt_bytes(
    salt: [u8; 16],
    nonce: [u8; 12],
    data: Vec<u8>,
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

    let decrypted_bytes = cipher.decrypt(nonce, data.as_slice());

    if decrypted_bytes.is_err() {
        return Err(anyhow!(
            "Unable to decrypt the data. Maybe it's a wrong key, or it's not an encrypted file."
        ));
    }

    Ok(decrypted_bytes.unwrap())
}

pub fn decrypt_bytes_stream(
    input: &mut File,
    output: &mut File,
    raw_key: Secret<Vec<u8>>,
    bench: bool,
    hash: bool,
) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; 8];
    input
        .read(&mut salt)
        .context("Unable to read salt from the file")?;
    input
        .read(&mut nonce)
        .context("Unable to read nonce from the file")?;

    let key = get_key(raw_key, salt)?;
    let nonce = Nonce::from_slice(nonce.as_slice());
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret());
    drop(key);

    if cipher.is_err() {
        return Err(anyhow!("Unable to create cipher with argon2id hashed key."));
    }

    let cipher = cipher.unwrap();

    let mut stream = DecryptorLE31::from_aead(cipher, nonce);

    let mut hasher = blake3::Hasher::new();
    hasher.update(&salt);
    hasher.update(nonce);

    let mut buffer = [0u8; BLOCK_SIZE + 16]; // 16 bytes is the length of the GCM tag

    loop {
        let read_count = input.read(&mut buffer)?;
        if read_count == (BLOCK_SIZE + 16) {
            let decrypted_data = stream.decrypt_next(buffer.as_slice());

            if decrypted_data.is_err() {
                return Err(anyhow!("Unable to decrypt the data. Maybe it's a wrong key, or it's not an encrypted file."));
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
            // if we read something less than 1040, and have hit the end of the file
            let decrypted_data = stream.decrypt_last(&buffer[..read_count]);

            if decrypted_data.is_err() {
                return Err(anyhow!("Unable to decrypt the final block of data. Maybe it's a wrong key, or it's not an encrypted file."));
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
