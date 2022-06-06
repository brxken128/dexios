use crate::crypto::primitives::MemoryCiphers;
use crate::global::secret::Secret;
use crate::global::states::{Algorithm};
use crate::global::structs::{Header, HeaderType};
use aead::{NewAead};
use aes_gcm::Aes256Gcm;
use anyhow::anyhow;
use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;
use rand::{prelude::StdRng, Rng, SeedableRng};

pub fn init_encryption_cipher(header_type: HeaderType, key: Secret<[u8; 32]>, salt: [u8; 16]) -> Result<(Header, MemoryCiphers)> {
    match header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 12]>();

            let header = Header {
                salt: salt,
                nonce: nonce_bytes.to_vec(),
                header_type,
            };

            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            Ok((header, MemoryCiphers::Aes256Gcm(Box::new(cipher))))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 24]>();

            let header = Header {
                salt: salt,
                nonce: nonce_bytes.to_vec(),
                header_type,
            };

            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            Ok((header, MemoryCiphers::XChaCha(Box::new(cipher))))
        }
        Algorithm::DeoxysII256 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 15]>();

            let header = Header {
                salt: salt,
                nonce: nonce_bytes.to_vec(),
                header_type,
            };

            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            Ok((header, MemoryCiphers::DeoxysII(Box::new(cipher))))
        }
    }
}