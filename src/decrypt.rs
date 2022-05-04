use crate::prompt::*;
use crate::structs::*;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Ok, Result};
use argon2::Argon2;
use argon2::Params;
use sha3::Digest;
use sha3::Sha3_512;
use std::time::Instant;
use std::{
    fs::{metadata, File},
    io::{BufReader, Read, Write},
    process::exit,
};

pub fn decrypt_file(
    input: &str,
    output: &str,
    keyfile: &str,
    sha_sum: bool,
    skip: bool,
) -> Result<()> {
    let mut use_keyfile = false;
    if !keyfile.is_empty() {
        use_keyfile = true;
    }

    if metadata(output).is_ok() {
        // if the output file exists
        let answer = get_answer(
            "Output file already exists, would you like to overwrite?",
            true,
            skip,
        )?;
        if !answer {
            exit(0);
        }
    }

    let file = File::open(input).context("Unable to open the input file")?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new(); // our file bytes
    reader
        .read_to_end(&mut data)
        .context("Unable to read the input file")?;
    drop(reader);

    if sha_sum {
        let mut hasher = Sha3_512::new();
        hasher
            .write_all(&data)
            .context("Unable to write to the sha3-512 buffer")?;
        let hash = hasher.finalize();
        let hash_b64 = base64::encode(hash);
        println!("Hash of the encrypted file is: {}", hash_b64);

        let answer = get_answer(
            "Would you like to continue with the decryption?",
            true,
            skip,
        )
        .context("Unable to read provided answer")?;
        if !answer {
            exit(0);
        }
    }

    let data_json: DexiosFile =
        serde_json::from_slice(&data).context("Unable to read JSON from input file")?;

    let raw_key = if !use_keyfile {
        // if we're not using a keyfile, read from stdin
        let input = rpassword::prompt_password("Password: ").context("Unable to read password")?;
        input.as_bytes().to_vec()
    } else {
        let file = File::open(keyfile).context("Error opening keyfile")?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new(); // our file bytes
        reader
            .read_to_end(&mut buffer)
            .context("Error reading keyfile")?;
        buffer.clone()
    };

    let mut key = [0u8; 32];
    let salt = base64::decode(data_json.salt).context("Error decoding the salt's base64")?;

    let start_time = Instant::now();

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::default(),
    );
    argon2
        .hash_password_into(&raw_key, &salt, &mut key)
        .expect("Unable to hash your password with argon2");

    let nonce_bytes =
        base64::decode(data_json.nonce).context("Error decoding the nonce's base64")?;
    let nonce = Nonce::from_slice(nonce_bytes.as_slice());
    let cipher_key = Key::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(cipher_key);
    let encrypted_bytes =
        base64::decode(data_json.data).context("Error decoding the data's base64")?;
    let decrypted_bytes = cipher
        .decrypt(nonce, encrypted_bytes.as_slice())
        .expect("Unable to decrypt the data - likely a wrong password.");

    drop(encrypted_bytes);

    let mut writer = File::create(output).context("Can't create output file")?;
    writer
        .write_all(&decrypted_bytes)
        .context("Can't write to the output file")?;
    writer.flush().context("Unable to flush output file")?;
    drop(writer);

    let duration = start_time.elapsed();

    println!(
        "Decryption successful - written to {} [took {:.2}s]",
        output,
        duration.as_secs_f32()
    );

    Ok(())
}
