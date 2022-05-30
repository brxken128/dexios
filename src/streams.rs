use crate::global::crypto::DecryptStreamCiphers;
use crate::global::enums::HeaderVersion;
use crate::global::structs::{Header, HeaderType};
use crate::global::{crypto::EncryptStreamCiphers, enums::Algorithm};
use crate::header::{sign, verify};
use crate::key::{argon2_hash, gen_salt};
use crate::secret::Secret;
use aead::stream::{DecryptorLE31, EncryptorLE31};
use aead::NewAead;
use aes_gcm::Aes256Gcm;
use anyhow::anyhow;
use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use deoxys::DeoxysII256;
use paris::success;
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use std::result::Result::Ok;

// this function hashes the provided key, and then initialises the stream ciphers
// it's used for encrypt/stream mode and is the central place for managing streams for encryption
pub fn init_encryption_stream(
    raw_key: Secret<Vec<u8>>,
    header_type: HeaderType,
) -> Result<(EncryptStreamCiphers, Header, Vec<u8>)> {
    let salt = gen_salt();
    let key = argon2_hash(raw_key, &salt, &header_type.header_version)?;

    match header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 8]>();

            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let header = Header{header_type, nonce: nonce_bytes.to_vec(), salt};
            let signature = sign(&header, key)?;

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::Aes256Gcm(Box::new(stream)),
                header,
                signature,
            ))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 20]>();

            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let header = Header{header_type, nonce: nonce_bytes.to_vec(), salt};
            let signature = sign(&header, key)?;

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::XChaCha(Box::new(stream)),
                header,
                signature,
            ))
        }
        Algorithm::DeoxysII256 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 11]>();

            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let header = Header{header_type, nonce: nonce_bytes.to_vec(), salt};
            let signature = sign(&header, key)?;

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::DeoxysII(Box::new(stream)),
                header,
                signature,
            ))
        }
    }
}

// this function hashes the provided key, and then initialises the stream ciphers
// it's used for decrypt/stream mode and is the central place for managing streams for decryption
pub fn init_decryption_stream(
    raw_key: Secret<Vec<u8>>,
    header: &Header,
    signature: Option<Vec<u8>>
) -> Result<DecryptStreamCiphers> {

    let key = argon2_hash(raw_key, &header.salt, &header.header_type.header_version)?;

    match header.header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            if header.header_type.header_version == HeaderVersion::V2 {
                if !verify(&header, signature.unwrap(), key)? {
                    // use newlines with this error as it'll be done on the same line due to paris otherwise
                    return Err(anyhow::anyhow!("\nHeader signature doesn't match or your password was incorrect"))
                }
            }

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::Aes256Gcm(Box::new(stream)))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            if header.header_type.header_version == HeaderVersion::V2 {
                if !verify(&header, signature.unwrap(), key)? {
                    return Err(anyhow::anyhow!("\nHeader signature doesn't match or your password was incorrect"))
                }
            }

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::XChaCha(Box::new(stream)))
        }
        Algorithm::DeoxysII256 => {
            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            if header.header_type.header_version == HeaderVersion::V2 {
                if !verify(&header, signature.unwrap(), key)? {
                    return Err(anyhow::anyhow!("\nHeader signature doesn't match or your password was incorrect"))
                }
            }

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::DeoxysII(Box::new(stream)))
        }
    }
}
