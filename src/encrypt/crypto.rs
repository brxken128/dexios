use crate::structs::DexiosFile;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key};
use argon2::Argon2;
use argon2::Params;
use rand::{prelude::StdRng, Rng, RngCore, SeedableRng};

fn gen_salt() -> [u8; 256] {
    let mut salt: [u8; 256] = [0; 256];
    StdRng::from_entropy().fill_bytes(&mut salt);

    salt
}

fn gen_key(raw_key: Vec<u8>) -> ([u8; 32], [u8; 256]) {
    let mut key = [0u8; 32];
    let salt = gen_salt();

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::default(),
    );
    argon2
        .hash_password_into(&raw_key, &salt, &mut key)
        .expect("Unable to hash your password with argon2");

    (key, salt)
}

fn gen_nonce() -> [u8; 12] {
    rand::thread_rng().gen::<[u8; 12]>()
}

pub fn encrypt_bytes(data: Vec<u8>, raw_key: Vec<u8>) -> DexiosFile {
    let nonce_bytes = gen_nonce();
    let nonce = GenericArray::from_slice(nonce_bytes.as_slice());

    let (key, salt) = gen_key(raw_key);
    let cipher_key = Key::from_slice(key.as_slice());

    let cipher = Aes256Gcm::new(cipher_key);
    let encrypted_bytes = cipher
        .encrypt(nonce, data.as_slice())
        .expect("Unable to encrypt the data");

    drop(data);

    let encrypted_bytes_base64 = base64::encode(encrypted_bytes);
    let salt_base64 = base64::encode(salt);
    let nonce_base64 = base64::encode(nonce);

    DexiosFile {
        salt: salt_base64,
        nonce: nonce_base64,
        data: encrypted_bytes_base64,
    }
}
