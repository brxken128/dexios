//! This module contains all of the LE31 STREAM objects and functionality
//!
//! This is where streaming mode encryption, decryption and initialization is handled.
//!
//! There are also some convenience functions for quickly encrypting and decrypting files.

use std::io::{Read, Write};

use aead::{
    stream::{DecryptorLE31, EncryptorLE31},
    NewAead, Payload,
};
use aes_gcm::Aes256Gcm;
use anyhow::Context;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;
use rand::{prelude::StdRng, Rng, SeedableRng};
use zeroize::Zeroize;

use crate::primitives::{Algorithm, BLOCK_SIZE};
use crate::protected::Protected;

/// This `enum` contains streams for that are used solely for encryption
/// It has definitions for all AEADs supported by `dexios-core`
pub enum EncryptionStreams {
    Aes256Gcm(Box<EncryptorLE31<Aes256Gcm>>),
    XChaCha20Poly1305(Box<EncryptorLE31<XChaCha20Poly1305>>),
    DeoxysII256(Box<EncryptorLE31<DeoxysII256>>),
}

/// This `enum` contains streams for that are used solely for decryption
/// It has definitions for all AEADs supported by `dexios-core`
pub enum DecryptionStreams {
    Aes256Gcm(Box<DecryptorLE31<Aes256Gcm>>),
    XChaCha20Poly1305(Box<DecryptorLE31<XChaCha20Poly1305>>),
    DeoxysII256(Box<DecryptorLE31<DeoxysII256>>),
}

impl EncryptionStreams {
    /// This method can be used to quickly create an `EncryptionStreams` object
    /// It requies a 32-byte hashed key, which will be dropped once the stream has been initialized
    /// It will create the stream with the specified algorithm, and it will also generate the appropriate nonce
    /// Both the nonce and the `EncryptionStreams` object are returned
    pub fn initialize(
        key: Protected<[u8; 32]>,
        algorithm: Algorithm,
    ) -> anyhow::Result<(Self, Vec<u8>)> {
        let (streams, nonce) = match algorithm {
            Algorithm::Aes256Gcm => {
                let nonce = StdRng::from_entropy().gen::<[u8; 8]>();

                let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "Unable to create cipher with argon2id hashed key."
                        ))
                    }
                };

                let stream = EncryptorLE31::from_aead(cipher, nonce.as_slice().into());
                (
                    EncryptionStreams::Aes256Gcm(Box::new(stream)),
                    nonce.to_vec(),
                )
            }
            Algorithm::XChaCha20Poly1305 => {
                let nonce = StdRng::from_entropy().gen::<[u8; 20]>();

                let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "Unable to create cipher with argon2id hashed key."
                        ))
                    }
                };

                let stream = EncryptorLE31::from_aead(cipher, nonce.as_slice().into());
                (
                    EncryptionStreams::XChaCha20Poly1305(Box::new(stream)),
                    nonce.to_vec(),
                )
            }
            Algorithm::DeoxysII256 => {
                let nonce = StdRng::from_entropy().gen::<[u8; 11]>();

                let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "Unable to create cipher with argon2id hashed key."
                        ))
                    }
                };

                let stream = EncryptorLE31::from_aead(cipher, nonce.as_slice().into());
                (
                    EncryptionStreams::DeoxysII256(Box::new(stream)),
                    nonce.to_vec(),
                )
            }
        };

        drop(key);
        Ok((streams, nonce))
    }

    /// This is used for encrypting the *next* block of data in streaming mode
    /// It requires either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    pub fn encrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptionStreams::Aes256Gcm(s) => s.encrypt_next(payload),
            EncryptionStreams::XChaCha20Poly1305(s) => s.encrypt_next(payload),
            EncryptionStreams::DeoxysII256(s) => s.encrypt_next(payload),
        }
    }

    /// This is used for encrypting the *last* block of data in streaming mode. It consumes the stream object to prevent further usage.
    /// It requires either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    pub fn encrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptionStreams::Aes256Gcm(s) => s.encrypt_last(payload),
            EncryptionStreams::XChaCha20Poly1305(s) => s.encrypt_last(payload),
            EncryptionStreams::DeoxysII256(s) => s.encrypt_last(payload),
        }
    }

    /// This is a convenience function for reading from a reader, encrypting, and writing to the writer.
    /// Every single block is provided with the AAD
    /// Valid AAD must be provided if you are using `HeaderVersion::V3` and above. It must be empty if the `HeaderVersion` is lower.
    /// You are free to use a custom AAD, just ensure that it is present for decryption, or else you will receive an error.
    /// This does not handle writing the header.
    pub fn encrypt_file(
        mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        aad: &[u8],
    ) -> anyhow::Result<()> {
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
                    aad,
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
                    aad,
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

impl DecryptionStreams {
    /// This method can be used to quickly create an `DecryptionStreams` object
    /// It requies a 32-byte hashed key, which will be dropped once the stream has been initialized
    /// It requires the same nonce that was returned upon initializing `EncryptionStreams`
    /// It will create the stream with the specified algorithm
    /// The `DecryptionStreams` object will be returned
    pub fn initialize(
        key: Protected<[u8; 32]>,
        nonce: &[u8],
        algorithm: Algorithm,
    ) -> anyhow::Result<Self> {
        let streams = match algorithm {
            Algorithm::Aes256Gcm => {
                let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                    Ok(cipher) => cipher,
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "Unable to create cipher with argon2id hashed key."
                        ))
                    }
                };

                let stream = DecryptorLE31::from_aead(cipher, nonce.into());
                DecryptionStreams::Aes256Gcm(Box::new(stream))
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

                let stream = DecryptorLE31::from_aead(cipher, nonce.into());
                DecryptionStreams::XChaCha20Poly1305(Box::new(stream))
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

                let stream = DecryptorLE31::from_aead(cipher, nonce.into());
                DecryptionStreams::DeoxysII256(Box::new(stream))
            }
        };

        drop(key);
        Ok(streams)
    }

    /// This is used for decrypting the *next* block of data in streaming mode
    /// It requires either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    /// Whatever you provided as AAD while encrypting must be present during decryption, or else you will receive an error.
    pub fn decrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptionStreams::Aes256Gcm(s) => s.decrypt_next(payload),
            DecryptionStreams::XChaCha20Poly1305(s) => s.decrypt_next(payload),
            DecryptionStreams::DeoxysII256(s) => s.decrypt_next(payload),
        }
    }

    /// This is used for decrypting the *last* block of data in streaming mode. It consumes the stream object to prevent further usage.
    /// It requires either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    /// Whatever you provided as AAD while encrypting must be present during decryption, or else you will receive an error.
    pub fn decrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptionStreams::Aes256Gcm(s) => s.decrypt_last(payload),
            DecryptionStreams::XChaCha20Poly1305(s) => s.decrypt_last(payload),
            DecryptionStreams::DeoxysII256(s) => s.decrypt_last(payload),
        }
    }

    /// This is a convenience function for reading from a reader, decrypting, and writing to the writer.
    /// Every single block is provided with the AAD
    /// Valid AAD must be provided if you are using `HeaderVersion::V3` and above. It must be empty if the `HeaderVersion` is lower. Whatever you provided as AAD while encrypting must be present during decryption, or else you will receive an error.
    /// This does not handle writing the header.
    pub fn decrypt_file(
        mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        aad: &[u8],
    ) -> anyhow::Result<()> {
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
