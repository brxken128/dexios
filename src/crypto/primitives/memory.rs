use aead::{
    Aead, NewAead, Payload,
};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;

use crate::global::{secret::Secret, states::Algorithm};

pub enum MemoryCiphers {
    Aes256Gcm(Box<Aes256Gcm>),
    XChaCha(Box<XChaCha20Poly1305>),
    DeoxysII(Box<DeoxysII256>),
}

impl MemoryCiphers {
    pub fn initialize(key: Secret<[u8; 32]>, algorithm: Algorithm) -> anyhow::Result<Self> {
        let cipher = match algorithm {
            Algorithm::Aes256Gcm => {
                let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "Unable to create cipher with argon2id hashed key."
                        ))
                    }
                };

                MemoryCiphers::Aes256Gcm(Box::new(cipher))
            }
            Algorithm::XChaCha20Poly1305 => {
                let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "Unable to create cipher with argon2id hashed key."
                        ))
                    }
                };

                MemoryCiphers::XChaCha(Box::new(cipher))
            }
            Algorithm::DeoxysII256 => {
                let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "Unable to create cipher with argon2id hashed key."
                        ))
                    }
                };

                MemoryCiphers::DeoxysII(Box::new(cipher))
            }
        };

        drop(key);
        Ok(cipher)
    }

    pub fn encrypt<'msg, 'aad>(
        &self,
        nonce: &[u8],
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            MemoryCiphers::Aes256Gcm(c) => c.encrypt(nonce.as_ref().into(), plaintext),
            MemoryCiphers::XChaCha(c) => c.encrypt(nonce.as_ref().into(), plaintext),
            MemoryCiphers::DeoxysII(c) => c.encrypt(nonce.as_ref().into(), plaintext),
        }
    }

    pub fn decrypt<'msg, 'aad>(
        &self,
        nonce: &[u8],
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            MemoryCiphers::Aes256Gcm(c) => c.decrypt(nonce.as_ref().into(), ciphertext),
            MemoryCiphers::XChaCha(c) => c.decrypt(nonce.as_ref().into(), ciphertext),
            MemoryCiphers::DeoxysII(c) => c.decrypt(nonce.as_ref().into(), ciphertext),
        }
    }
}