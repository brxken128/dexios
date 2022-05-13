use crate::file::get_file_bytes;
use anyhow::{Context, Ok, Result};

fn get_password_with_validation() -> Result<Vec<u8>> {
    Ok(loop {
        let input = rpassword::prompt_password("Password: ").context("Unable to read password")?;
        let input_validation = rpassword::prompt_password("Password (for validation): ")
            .context("Unable to read password")?;

        if input == input_validation && !input.is_empty() {
            break input.as_bytes().to_vec();
        } else if input.is_empty() {
            println!("Password cannot be empty, please try again.");
        } else {
            println!("The passwords aren't the same, please try again.");
        }
    })
}

pub fn get_user_key(keyfile: &str) -> Result<Vec<u8>> {
    Ok(if !keyfile.is_empty() {
        println!("Reading key from {}", keyfile);
        get_file_bytes(keyfile)?
    } else if std::env::var("DEXIOS_KEY").is_ok() {
        println!("Reading key from DEXIOS_KEY environment variable");
        std::env::var("DEXIOS_KEY")
            .context("Unable to read DEXIOS_KEY from environment variable")?
            .into_bytes()
    } else {
        println!("Reading key from stdin");
        get_password_with_validation()?
    })
}
