use crate::prompt::*;
use crate::structs::*;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Ok, Result};
use argon2::Argon2;
use argon2::Params;
use rand::{prelude::StdRng, Rng, RngCore, SeedableRng};
use sha3::Digest;
use sha3::Sha3_512;
use std::time::Instant;
use std::{
    fs::{metadata, File},
    io::{BufReader, Read, Write},
    process::exit,
};

pub fn encrypt_file(
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
        )
        .context("Unable to read provided answer")?;
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

    let raw_key = if !use_keyfile {
        loop {
            let input =
                rpassword::prompt_password("Password: ").context("Unable to read password")?;
            let input_validation = rpassword::prompt_password("Password (for validation): ")
                .context("Unable to read password")?;
            if input == input_validation {
                break input.as_bytes().to_vec();
            } else {
                println!("The passwords aren't the same, please try again.");
            }
        }
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

    let mut salt: [u8; 256] = [0; 256];
    StdRng::from_entropy().fill_bytes(&mut salt);

    let start_time = Instant::now();

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::default(),
    );
    argon2
        .hash_password_into(&raw_key, &salt, &mut key)
        .expect("Unable to hash your password with argon2");

    let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(nonce_bytes.as_slice());
    let cipher_key = Key::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(cipher_key);
    let encrypted_bytes = cipher
        .encrypt(nonce, data.as_slice())
        .expect("Unable to encrypt the data");

    drop(data);

    let encrypted_bytes_base64 = base64::encode(encrypted_bytes);
    let salt_base64 = base64::encode(salt);
    let nonce_base64 = base64::encode(nonce);

    let data = DexiosFile {
        salt: salt_base64,
        nonce: nonce_base64,
        data: encrypted_bytes_base64,
    };

    let mut writer = File::create(output).context("Can't create output file")?;
    serde_json::to_writer(&writer, &data).context("Can't write to the output file")?;
    writer.flush().context("Unable to flush output file")?;

    let duration = start_time.elapsed();

    println!(
        "Encryption successful - written to {} [took {:.2}s]",
        output,
        duration.as_secs_f32()
    );

    if sha_sum {
        let mut hasher = Sha3_512::new();
        serde_json::to_writer(&mut hasher, &data).context("Can't write to the sha3-512 hasher")?;
        let hash = hasher.finalize();
        let hash_b64 = base64::encode(hash);
        println!("Hash of the encrypted file is: {}", hash_b64);
    }

    Ok(())
}
