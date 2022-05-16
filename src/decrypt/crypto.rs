use std::fs::File;

use crate::global::DexiosFile;
use aes_gcm::aead::stream::DecryptorLE31;
use anyhow::Result;

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Context;
use anyhow::Ok;
use argon2::Argon2;
use argon2::Params;
use std::io::Read;
use std::io::Write;

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

    let decrypted_bytes = cipher.decrypt(nonce, data.data.as_slice()).expect(
        "Unable to decrypt the data - likely a wrong password or it's not a dexios-encrypted file.",
    );

    Ok(decrypted_bytes)
}

pub fn decrypt_bytes_stream(
    input: &mut File,
    output: &mut File,
    raw_key: Vec<u8>,
    bench: bool,
) -> Result<()> {
    let mut salt = [0u8; 256];
    let mut nonce = [0u8; 8];
    input
        .read(&mut salt)
        .context("Unable to read salt from the file")?;
    input
        .read(&mut nonce)
        .context("Unable to read nonce from the file")?;

    let key = get_key(raw_key, salt);
    let nonce = Nonce::from_slice(nonce.as_slice());
    let cipher_key = Key::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(cipher_key);
    let mut stream = DecryptorLE31::from_aead(cipher, nonce);

    let mut buffer = [0u8; 1024 + 16]; // 16 bytes is the length of the GCM tag

    loop {
        let read_count = input.read(&mut buffer)?;
        if read_count == (1024 + 16) {
            let encrypted_data = stream
                .decrypt_next(buffer.as_slice())
                .expect("Unable to decrypt block");
            if !bench {
                output
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output file")?;
            }
        } else {
            // if we read something less than 1040, and have hit the end of the file
            let encrypted_data = stream
                .decrypt_last(&buffer[..read_count])
                .expect("Unable to decrypt final block");
            if !bench {
                output
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output file")?;
                output.flush().context("Unable to flush the output file")?;
            }
            break;
        }
    }

    Ok(())
}
