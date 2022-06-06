use crate::crypto::primitives::{DecryptStreamCiphers, EncryptStreamCiphers};
use crate::global::secret::Secret;
use crate::global::states::Algorithm;
use aead::stream::{DecryptorLE31, EncryptorLE31};
use aead::NewAead;
use aes_gcm::Aes256Gcm;
use anyhow::anyhow;
use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use std::result::Result::Ok;

// this file initialises encryption streams
// it also handles V2 header's signing
// it handles HMAC here so we don't have to re-hash or clone the key

// this function hashes the provided key, and then initialises the stream ciphers
// it's used for encrypt/stream mode and is the central place for managing streams for encryption
pub fn init_encryption_stream(
    key: Secret<[u8; 32]>,
    algorithm: &Algorithm,
) -> Result<(EncryptStreamCiphers, Vec<u8>)> {
    match algorithm {
        Algorithm::Aes256Gcm => {
            let nonce = StdRng::from_entropy().gen::<[u8; 8]>();

            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce.as_slice().into());
            Ok((
                EncryptStreamCiphers::Aes256Gcm(Box::new(stream)),
                nonce.to_vec(),
            ))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce = StdRng::from_entropy().gen::<[u8; 20]>();

            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce.as_slice().into());
            Ok((
                EncryptStreamCiphers::XChaCha(Box::new(stream)),
                nonce.to_vec(),
            ))
        }
        Algorithm::DeoxysII256 => {
            let nonce = StdRng::from_entropy().gen::<[u8; 11]>();

            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce.as_slice().into());
            Ok((
                EncryptStreamCiphers::DeoxysII(Box::new(stream)),
                nonce.to_vec(),
            ))
        }
    }
}

// this function hashes the provided key, and then initialises the stream ciphers
// it's used for decrypt/stream mode and is the central place for managing streams for decryption
pub fn init_decryption_stream(
    key: Secret<[u8; 32]>,
    nonce: &[u8],
    algorithm: &Algorithm,
) -> Result<DecryptStreamCiphers> {
    match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, nonce.into());
            Ok(DecryptStreamCiphers::Aes256Gcm(Box::new(stream)))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, nonce.into());
            Ok(DecryptStreamCiphers::XChaCha(Box::new(stream)))
        }
        Algorithm::DeoxysII256 => {
            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, nonce.into());
            Ok(DecryptStreamCiphers::DeoxysII(Box::new(stream)))
        }
    }
}
