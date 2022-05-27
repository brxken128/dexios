use anyhow::Result;
use rand::prelude::StdRng;

use crate::global::{crypto::EncryptStreamCiphers, parameters::Algorithm};


use crate::global::parameters::HeaderType;
use crate::global::{SALT_LEN};
use crate::key::{argon2_hash, gen_salt};
use crate::secret::Secret;
use aead::stream::EncryptorLE31;
use aead::{NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use chacha20poly1305::{XChaCha20Poly1305};
use deoxys::DeoxysII256;
use rand::{Rng, SeedableRng};
use std::result::Result::Ok;


pub fn init_encryption_stream(raw_key: Secret<Vec<u8>>, header_type: &HeaderType) -> Result<(EncryptStreamCiphers, [u8; SALT_LEN], Vec<u8>)> {
    let salt = gen_salt();

    match header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 8]>();
            let nonce = Nonce::from_slice(&nonce_bytes);
    
            let key = argon2_hash(raw_key, &salt, &header_type.header_version)?;
            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };
    
            let stream = EncryptorLE31::from_aead(cipher, nonce);
            Ok((
                EncryptStreamCiphers::Aes256Gcm(Box::new(stream)),
                salt,
                nonce_bytes.to_vec(),
            ))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 20]>();
    
            let key = argon2_hash(raw_key, &salt, &header_type.header_version)?;
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };
    
            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::XChaCha(Box::new(stream)),
                salt,
                nonce_bytes.to_vec(),
            ))
        }
        Algorithm::DeoxysII256 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 11]>();
    
            let key = argon2_hash(raw_key, &salt, &header_type.header_version)?;
            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => {
                    drop(key);
                    cipher
                }
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };
    
            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::DeoxysII(Box::new(stream)),
                salt,
                nonce_bytes.to_vec(),
            ))
        }
    }
}