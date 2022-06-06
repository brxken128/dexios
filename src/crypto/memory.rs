use crate::crypto::primitives::MemoryCiphers;
use crate::global::secret::Secret;
use crate::global::states::{Algorithm};
use aead::{NewAead};
use aes_gcm::Aes256Gcm;
use anyhow::anyhow;
use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;

pub fn init_memory_cipher(key: Secret<[u8; 32]>, algorithm: &Algorithm) -> Result<MemoryCiphers> {
    let cipher = match algorithm {
        Algorithm::Aes256Gcm => {

            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            MemoryCiphers::Aes256Gcm(Box::new(cipher))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            MemoryCiphers::XChaCha(Box::new(cipher))
        }
        Algorithm::DeoxysII256 => {
            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            MemoryCiphers::DeoxysII(Box::new(cipher))
        }
    };

    Ok(cipher)
}