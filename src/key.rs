use crate::file::get_bytes;
use crate::global::parameters::HeaderVersion;
use crate::global::parameters::PasswordMode;
use crate::global::SALT_LEN;
use anyhow::{Context, Ok, Result};
use argon2::Argon2;
use secrecy::ExposeSecret;
use secrecy::Secret;
use secrecy::SecretVec;
use secrecy::Zeroize;

// this handles argon2 hashing with the provided key
// it returns the key hashed with a specified salt
pub fn argon2_hash(raw_key: Secret<Vec<u8>>, salt: &[u8; SALT_LEN], version: &HeaderVersion) -> Result<Secret<[u8; 32]>> {
    let mut key = [0u8; 32];

    let params = match version {
        HeaderVersion::V1 => {
            let params = argon2::ParamsBuilder::new();
            params.t_cost(6); // number of iterations
            params.p_cost(4); // parallelism
            match params.params() {
                std::result::Result::Ok(parameters) => parameters,
                Err(_) => return Err(anyhow::anyhow!("Error initialising argon2id parameters")),
            }
        }
    };

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    let result = argon2.hash_password_into(raw_key.expose_secret(), salt, &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(anyhow::anyhow!(
            "Error while hashing your password with argon2id"
        ));
    }

    Ok(Secret::new(key))
}

// this interactively gets the user's password from the terminal
// it takes the password twice, compares, and returns the bytes
fn get_password(validation: bool) -> Result<Secret<Vec<u8>>> {
    Ok(loop {
        let input = rpassword::prompt_password("Password: ").context("Unable to read password")?;
        if !validation {
            return Ok(SecretVec::new(input.into_bytes()));
        }

        let mut input_validation = rpassword::prompt_password("Password (for validation): ")
            .context("Unable to read password")?;

        if input == input_validation && !input.is_empty() {
            input_validation.zeroize();
            break SecretVec::new(input.into_bytes());
        } else if input.is_empty() {
            println!("Password cannot be empty, please try again.");
        } else {
            println!("The passwords aren't the same, please try again.");
        }
    })
}

// this takes in the keyfile string - if if's not empty, get those bytes
// next, if the env var DEXIOS_KEY is set, retrieve the value
// if neither of the above are true, ask the user for their specified key
// if validation is true, call get_password_with_validation and require it be entered twice
// if not, just get the key once
#[allow(clippy::module_name_repetitions)] // possibly temporary - need a way to handle this (maybe key::handler?)
pub fn get_user_key(
    keyfile: &str,
    validation: bool,
    password: PasswordMode,
) -> Result<Secret<Vec<u8>>> {
    Ok(if !keyfile.is_empty() {
        println!("Reading key from {}", keyfile);
        get_bytes(keyfile)?
    } else if std::env::var("DEXIOS_KEY").is_ok()
        && password == PasswordMode::NormalKeySourcePriority
    {
        println!("Reading key from DEXIOS_KEY environment variable");
        SecretVec::new(
            std::env::var("DEXIOS_KEY")
                .context("Unable to read DEXIOS_KEY from environment variable")?
                .into_bytes(),
        )
    } else {
        get_password(validation)?
    })
}
