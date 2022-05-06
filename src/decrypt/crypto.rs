use anyhow::Result;
use crate::structs::DexiosFile;

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Ok};
use argon2::Argon2;
use argon2::Params;


fn get_key(raw_key: Vec<u8>, salt: Vec<u8>) -> [u8; 32] {
    let mut key = [0u8; 32];

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::default(),
    );
    argon2
        .hash_password_into(&raw_key, &salt, &mut key)
        .expect("Unable to hash your password with argon2");

    return key;
}

fn get_information(data: &DexiosFile) -> Result<(Vec<u8>, Vec<u8>)> {
    let salt = base64::decode(&data.salt).context("Error decoding the salt's base64")?;

    let nonce_bytes =
        base64::decode(&data.nonce).context("Error decoding the nonce's base64")?;

    Ok((salt, nonce_bytes))
}

pub fn decrypt_bytes(data: DexiosFile, raw_key: Vec<u8>) -> Result<Vec<u8>> {
    let (salt, nonce_bytes) = get_information(&data)?;
    let key = get_key(raw_key, salt);

    let nonce = Nonce::from_slice(nonce_bytes.as_slice());
    let cipher_key = Key::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(cipher_key);

    let encrypted_bytes =
        base64::decode(&data.data).context("Error decoding the data's base64")?;
    
    drop(data);

    let decrypted_bytes = cipher
        .decrypt(nonce, encrypted_bytes.as_slice())
        .expect("Unable to decrypt the data - likely a wrong password.");
    
    Ok(decrypted_bytes)
}



