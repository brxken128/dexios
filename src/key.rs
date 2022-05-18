use crate::file::get_file_bytes;
use anyhow::{Context, Ok, Result};
use secrecy::Secret;
use secrecy::SecretVec;
use secrecy::Zeroize;

fn get_password_with_validation() -> Result<Vec<u8>> {
    Ok(loop {
        let input = rpassword::prompt_password("Password: ").context("Unable to read password")?;
        let mut input_validation = rpassword::prompt_password("Password (for validation): ")
            .context("Unable to read password")?;

        if input == input_validation && !input.is_empty() {
            input_validation.zeroize();
            break input.into_bytes()
        } else if input.is_empty() {
            println!("Password cannot be empty, please try again.");
        } else {
            println!("The passwords aren't the same, please try again.");
        }
    })
}

pub fn get_user_key_encrypt(keyfile: &str) -> Result<Secret<Vec<u8>>> {
    Ok(if !keyfile.is_empty() {
        println!("Reading key from {}", keyfile);
        SecretVec::new(get_file_bytes(keyfile)?)
    } else if std::env::var("DEXIOS_KEY").is_ok() {
        println!("Reading key from DEXIOS_KEY environment variable");
        SecretVec::new(
            std::env::var("DEXIOS_KEY")
                .context("Unable to read DEXIOS_KEY from environment variable")?
                .into_bytes(),
        )
    } else {
        println!("Reading key from the terminal");
        SecretVec::new(get_password_with_validation()?)
    })
}

pub fn get_user_key_decrypt(keyfile: &str) -> Result<Secret<Vec<u8>>> {
    Ok(if !keyfile.is_empty() {
        println!("Reading key from {}", keyfile);
        SecretVec::new(get_file_bytes(keyfile)?)
    } else if std::env::var("DEXIOS_KEY").is_ok() {
        println!("Reading key from DEXIOS_KEY environment variable");
        SecretVec::new(
            std::env::var("DEXIOS_KEY")
                .context("Unable to read DEXIOS_KEY from environment variable")?
                .into_bytes(),
        )
    } else {
        println!("Reading key from the terminal");
        let input = rpassword::prompt_password("Password: ").context("Unable to read password")?;
        SecretVec::new(input.into_bytes())
    })
}
