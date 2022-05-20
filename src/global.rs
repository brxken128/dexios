use aead::{stream::{EncryptorLE31, DecryptorLE31}, Payload, Result};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;

// this file sets constants that are used throughout the codebase
// these can be customised easily by anyone to suit there own needs
pub const BLOCK_SIZE: usize = 1_048_576; // 1024*1024 bytes
pub const SALT_LEN: usize = 16; // bytes

#[derive(PartialEq)]
pub enum CipherType {
    AesGcm,
    XChaCha20Poly1305,
}


pub enum EncryptStreamCiphers {
    AesGcm(EncryptorLE31<Aes256Gcm>),
    XChaCha(EncryptorLE31<XChaCha20Poly1305>),
}

pub enum DecryptStreamCiphers {
    AesGcm(DecryptorLE31<Aes256Gcm>),
    XChaCha(DecryptorLE31<XChaCha20Poly1305>),
}

impl EncryptStreamCiphers {
    pub fn encrypt_next<'msg, 'aad>(&mut self, payload: impl Into<Payload<'msg, 'aad>>) -> Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::AesGcm(s) => s.encrypt_next(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_next(payload),
        }
    }

    pub fn encrypt_last<'msg, 'aad>(self, payload: impl Into<Payload<'msg, 'aad>>) -> Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::AesGcm(s) => s.encrypt_last(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_last(payload),
        }
    }
}

impl DecryptStreamCiphers {
    pub fn decrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::AesGcm(s) => s.decrypt_next(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_next(payload),
        }
    }

    pub fn decrypt_last<'msg, 'aad>(self, payload: impl Into<Payload<'msg, 'aad>>) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::AesGcm(s) => s.decrypt_last(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_last(payload),
        }
    }
}