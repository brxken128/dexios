// this file contains all of the AEAD cryptographic enums/impls
// you can add other ciphers to the mix mainly in here, if you so wish
// they just need to be part of the RustCrypto "family"
// https://github.com/RustCrypto/AEADs

use std::io::{Read, Write};

use aead::{
    stream::{DecryptorLE31, EncryptorLE31},
    Aead, Payload, NewAead,
};
use aes_gcm::Aes256Gcm;
use anyhow::Context;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;
use rand::{prelude::StdRng, SeedableRng, Rng};
use zeroize::Zeroize;

use crate::global::{BLOCK_SIZE, secret::Secret, states::Algorithm};

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
    pub fn initialise(key: Secret<[u8; 32]>, algorithm: Algorithm) -> anyhow::Result<(Self, Vec<u8>)> {
        let (streams, nonce) = match algorithm {
            Algorithm::Aes256Gcm => {
                let nonce = StdRng::from_entropy().gen::<[u8; 8]>();
    
                let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => return Err(anyhow::anyhow!("Unable to create cipher with argon2id hashed key.")),
                };
    
                let stream = EncryptorLE31::from_aead(cipher, nonce.as_slice().into());
                (
                    EncryptStreamCiphers::Aes256Gcm(Box::new(stream)),
                    nonce.to_vec(),
                )
            }
            Algorithm::XChaCha20Poly1305 => {
                let nonce = StdRng::from_entropy().gen::<[u8; 20]>();
    
                let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => return Err(anyhow::anyhow!("Unable to create cipher with argon2id hashed key.")),
                };
    
                let stream = EncryptorLE31::from_aead(cipher, nonce.as_slice().into());
                (
                    EncryptStreamCiphers::XChaCha(Box::new(stream)),
                    nonce.to_vec(),
                )
            }
            Algorithm::DeoxysII256 => {
                let nonce = StdRng::from_entropy().gen::<[u8; 11]>();
    
                let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => return Err(anyhow::anyhow!("Unable to create cipher with argon2id hashed key.")),
                };
    
                let stream = EncryptorLE31::from_aead(cipher, nonce.as_slice().into());
                (
                    EncryptStreamCiphers::DeoxysII(Box::new(stream)),
                    nonce.to_vec(),
                )
            }
        };
    
        drop(key);
        Ok((streams, nonce.to_vec()))
    }
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

    // convenience function for quickly encrypting and writing to provided output
    pub fn encrypt_file(mut self, reader: &mut impl Read, writer: &mut impl Write, aad: &[u8]) -> anyhow::Result<()> {
        let mut read_buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();
        loop {
            let read_count = reader
                .read(&mut read_buffer)
                .context("Unable to read from the reader")?;
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
                    .context("Unable to write to the output")?;
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
                    .context("Unable to write to the output")?;
                break;
            }
        }
        read_buffer.zeroize();
        writer.flush().context("Unable to flush the output")?;

        Ok(())
    }
}

impl DecryptStreamCiphers {
    pub fn initialize(key: Secret<[u8; 32]>, nonce: &[u8], algorithm: Algorithm) -> anyhow::Result<Self> {
        let streams = match algorithm {
            Algorithm::Aes256Gcm => {
                let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => return Err(anyhow::anyhow!("Unable to create cipher with argon2id hashed key.")),
                };
    
                let stream = DecryptorLE31::from_aead(cipher, nonce.into());
                DecryptStreamCiphers::Aes256Gcm(Box::new(stream))
            }
            Algorithm::XChaCha20Poly1305 => {
                let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => return Err(anyhow::anyhow!("Unable to create cipher with argon2id hashed key.")),
                };
    
                let stream = DecryptorLE31::from_aead(cipher, nonce.into());
                DecryptStreamCiphers::XChaCha(Box::new(stream))
            }
            Algorithm::DeoxysII256 => {
                let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => return Err(anyhow::anyhow!("Unable to create cipher with argon2id hashed key.")),
                };
    
                let stream = DecryptorLE31::from_aead(cipher, nonce.into());
                DecryptStreamCiphers::DeoxysII(Box::new(stream))
            }
        };
    
        drop(key);
        Ok(streams)
    }
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

    // convenience function for decrypting a file and writing it to the output
    pub fn decrypt_file(mut self, reader: &mut impl Read, writer: &mut impl Write, aad: &[u8]) -> anyhow::Result<()> {
        let mut buffer = vec![0u8; BLOCK_SIZE + 16].into_boxed_slice();
        loop {
            let read_count = reader.read(&mut buffer)?;
            if read_count == (BLOCK_SIZE + 16) {
                let payload = Payload {
                    aad,
                    msg: buffer.as_ref(),
                };
    
                let mut decrypted_data = match self.decrypt_next(payload) {
                    Ok(bytes) => bytes,
                    Err(_) => return Err(anyhow::anyhow!("Unable to decrypt the data. This means either: you're using the wrong key, this isn't an encrypted file, or the header has been tampered with.")),
                };
    
                writer
                    .write_all(&decrypted_data)
                    .context("Unable to write to the output")?;
    
                decrypted_data.zeroize();
            } else {
                // if we read something less than BLOCK_SIZE+16, and have hit the end of the file
                let payload = Payload {
                    aad,
                    msg: &buffer[..read_count],
                };
    
                let mut decrypted_data = match self.decrypt_last(payload) {
                    Ok(bytes) => bytes,
                    Err(_) => return Err(anyhow::anyhow!("Unable to decrypt the final block of data. This means either: you're using the wrong key, this isn't an encrypted file, or the header has been tampered with.")),
                };
    
                writer
                    .write_all(&decrypted_data)
                    .context("Unable to write to the output file")?;

                decrypted_data.zeroize();
                break;
            }
        }

        writer.flush().context("Unable to flush the output")?;

        Ok(())
    }
}
