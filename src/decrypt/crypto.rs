use crate::structs::DexiosFile;
use anyhow::Result;

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Ok;
use argon2::Argon2;
use argon2::Params;

fn get_key(raw_key: Vec<u8>, salt: [u8; 256]) -> [u8; 32] {
    let mut key = [0u8; 32];

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::default(),
    );
    argon2
        .hash_password_into(&raw_key, &salt, &mut key)
        .expect("Unable to hash your password with argon2id");

    key
}

pub fn decrypt_bytes(data: DexiosFile, raw_key: Vec<u8>) -> Result<Vec<u8>> {
    let key = get_key(raw_key, data.salt);

    let nonce = Nonce::from_slice(data.nonce.as_slice());
    let cipher_key = Key::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(cipher_key);

    let decrypted_bytes = cipher
        .decrypt(nonce, data.data.as_slice())
        .expect("Unable to decrypt the data - likely a wrong password or it's not a dexios-encrypted file.");

    Ok(decrypted_bytes)
}
