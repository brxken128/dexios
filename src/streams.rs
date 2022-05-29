use crate::global::crypto::DecryptStreamCiphers;
use crate::global::structs::{Header, HeaderType};
use crate::global::SALT_LEN;
use crate::global::{crypto::EncryptStreamCiphers, enums::Algorithm};
use crate::key::{argon2_hash, gen_salt};
use crate::secret::Secret;
use aead::stream::{DecryptorLE31, EncryptorLE31};
use aead::NewAead;
use aes_gcm::{Aes256Gcm};
use anyhow::anyhow;
use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use std::result::Result::Ok;

// this function hashes the provided key, and then initialises the stream ciphers
// it's used for encrypt/stream mode and is the central place for managing streams for encryption
pub fn init_encryption_stream(
    raw_key: Secret<Vec<u8>>,
    header_type: &HeaderType,
) -> Result<(EncryptStreamCiphers, [u8; SALT_LEN], Vec<u8>)> {
    let salt = gen_salt();
    let key = argon2_hash(raw_key, &salt, &header_type.header_version)?;

    match header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 8]>();

            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::Aes256Gcm(Box::new(stream)),
                salt,
                nonce_bytes.to_vec(),
            ))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 20]>();

            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::XChaCha(Box::new(stream)),
                salt,
                nonce_bytes.to_vec(),
            ))
        }
        Algorithm::DeoxysII256 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 11]>();

            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::DeoxysII(Box::new(stream)),
                salt,
                nonce_bytes.to_vec(),
            ))
        }
    }
}

// this function hashes the provided key, and then initialises the stream ciphers
// it's used for decrypt/stream mode and is the central place for managing streams for decryption
pub fn init_decryption_stream(
    raw_key: Secret<Vec<u8>>,
    header: &Header,
) -> Result<DecryptStreamCiphers> {
    let key = argon2_hash(raw_key, &header.salt, &header.header_type.header_version)?;

    match header.header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::Aes256Gcm(Box::new(stream)))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::XChaCha(Box::new(stream)))
        }
        Algorithm::DeoxysII256 => {
            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::DeoxysII(Box::new(stream)))
        }
    }
}
