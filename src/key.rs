use crate::file::get_bytes;
use crate::global::PasswordMode;
use anyhow::{Context, Ok, Result};
use secrecy::Secret;
use secrecy::SecretVec;
use secrecy::Zeroize;

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
        get_bytes(keyfile)? // already a secret
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
        get_password(validation)? // already a secret
    })
}
