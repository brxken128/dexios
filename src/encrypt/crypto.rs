use std::fs::File;

use crate::structs::DexiosFile;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, NewAead, stream::EncryptorLE31};
use aes_gcm::{Aes256Gcm, Key};
use anyhow::Ok;
use anyhow::Result;
use argon2::Argon2;
use argon2::Params;
use std::io::Write;
use std::io::Read;
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
        .expect("Unable to hash your password with argon2id");

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

    DexiosFile {
        salt,
        nonce: nonce_bytes,
        data: encrypted_bytes,
    }
}

pub fn encrypt_bytes_stream(input: &mut File, output: &mut File, raw_key: Vec<u8>, bench: bool) -> Result<()> {
    let nonce_bytes = rand::thread_rng().gen::<[u8; 8]>(); // only 8 because the last 4 the 32-bit AEAD counters
    let nonce = GenericArray::from_slice(nonce_bytes.as_slice());

    let (key, salt) = gen_key(raw_key);
    let cipher_key = Key::from_slice(key.as_slice());

    let cipher = Aes256Gcm::new(cipher_key);
    let mut stream = EncryptorLE31::from_aead(cipher, &nonce);

    if !bench {
        output.write_all(&salt)?;
        output.write_all(&nonce_bytes)?;
    }

    let mut buffer = [0u8; 1024];

    loop {
        let read_count = input.read(&mut buffer)?;
        if read_count == 1024 {
            let encrypted_data = stream.encrypt_next(buffer.as_slice()).unwrap();
            if !bench { output.write_all(&encrypted_data)?; }
        } else { // if we read something less than 1024, and have hit the end of the file
            let encrypted_data = stream.encrypt_last(buffer.as_slice()).unwrap();
            if !bench { output.write_all(&encrypted_data)?; }
            break;
        }
    }
    if !bench {
        output.flush()?;
    }
    Ok(())
}