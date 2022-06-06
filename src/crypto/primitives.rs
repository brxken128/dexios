// this file contains all of the AEAD cryptographic enums/impls
// you can add other ciphers to the mix mainly in here, if you so wish
// they just need to be part of the RustCrypto "family"
// https://github.com/RustCrypto/AEADs

use std::io::{Read, Write};

use aead::{
    stream::{DecryptorLE31, EncryptorLE31},
    Aead, Payload,
};
use aes_gcm::Aes256Gcm;
use anyhow::Context;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;
use zeroize::Zeroize;

use crate::global::BLOCK_SIZE;

pub enum MemoryCiphers {
    Aes256Gcm(Box<Aes256Gcm>),
    XChaCha(Box<XChaCha20Poly1305>),
    DeoxysII(Box<DeoxysII256>),
}

impl MemoryCiphers {
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

    // convenience function for quickly encrypting and writing
    pub fn encrypt_file(mut self, reader: &mut impl Read, writer: &mut impl Write, aad: &[u8]) -> anyhow::Result<()> {
        let mut read_buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();
        loop {
            let read_count = reader
                .read(&mut read_buffer)
                .context("Unable to read from the reader file")?;
            if read_count == BLOCK_SIZE {
                // aad is just empty bytes normally
                // create_aad returns empty bytes if the header isn't V3+
                // this means we don't need to do anything special in regards to older versions
                let payload = Payload {
                    aad: &aad,
                    msg: read_buffer.as_ref(),
                };
    
                let encrypted_data = match self.encrypt_next(payload) {
                    Ok(bytes) => bytes,
                    Err(_) => return Err(anyhow::anyhow!("Unable to encrypt the data")),
                };
    
                writer
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output file")?;
            } else {
                // if we read something less than BLOCK_SIZE, and have hit the end of the file
                let payload = Payload {
                    aad: &aad,
                    msg: &read_buffer[..read_count],
                };
    
                let encrypted_data = match self.encrypt_last(payload) {
                    Ok(bytes) => bytes,
                    Err(_) => return Err(anyhow::anyhow!("Unable to encrypt the data")),
                };
    
                writer
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output file")?;
                break;
            }
        }

        read_buffer.zeroize();

        Ok(())
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
