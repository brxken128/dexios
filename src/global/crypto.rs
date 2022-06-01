// this file contains all of the AEAD cryptographic enums/impls
// you can add other ciphers to the mix mainly in here, if you so wish
// they just need to be part of the RustCrypto "family"
// https://github.com/RustCrypto/AEADs

use aead::{
    stream::{DecryptorLE31, EncryptorLE31},
    Payload, Aead,
};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;

pub enum EncryptMemoryCiphers {
    Aes256Gcm(Box<Aes256Gcm>),
    XChaCha(Box<XChaCha20Poly1305>),
    DeoxysII(Box<DeoxysII256>),
}

impl EncryptMemoryCiphers {
    pub fn encrypt<'msg, 'aad>(
        &self,
        nonce: &[u8],
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptMemoryCiphers::Aes256Gcm(c) => c.encrypt(nonce.as_ref().into(), plaintext),
            EncryptMemoryCiphers::XChaCha(c) => c.encrypt(nonce.as_ref().into(), plaintext),
            EncryptMemoryCiphers::DeoxysII(c) => c.encrypt(nonce.as_ref().into(), plaintext),
        }
    }
}

pub enum EncryptStreamCiphers {
    Aes256Gcm(Box<EncryptorLE31<Aes256Gcm>>),
    XChaCha(Box<EncryptorLE31<XChaCha20Poly1305>>),
    DeoxysII(Box<EncryptorLE31<DeoxysII256>>),
}

pub enum DecryptStreamCiphers {
    Aes256Gcm(Box<DecryptorLE31<Aes256Gcm>>),
    XChaCha(Box<DecryptorLE31<XChaCha20Poly1305>>),
    DeoxysII(Box<DecryptorLE31<DeoxysII256>>),
}

impl EncryptStreamCiphers {
    pub fn encrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::Aes256Gcm(s) => s.encrypt_next(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_next(payload),
            EncryptStreamCiphers::DeoxysII(s) => s.encrypt_next(payload),
        }
    }

    pub fn encrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptStreamCiphers::Aes256Gcm(s) => s.encrypt_last(payload),
            EncryptStreamCiphers::XChaCha(s) => s.encrypt_last(payload),
            EncryptStreamCiphers::DeoxysII(s) => s.encrypt_last(payload),
        }
    }
}

impl DecryptStreamCiphers {
    pub fn decrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::Aes256Gcm(s) => s.decrypt_next(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_next(payload),
            DecryptStreamCiphers::DeoxysII(s) => s.decrypt_next(payload),
        }
    }

    pub fn decrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptStreamCiphers::Aes256Gcm(s) => s.decrypt_last(payload),
            DecryptStreamCiphers::XChaCha(s) => s.decrypt_last(payload),
            DecryptStreamCiphers::DeoxysII(s) => s.decrypt_last(payload),
        }
    }
}
