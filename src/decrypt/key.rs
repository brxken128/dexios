use crate::file::get_file_bytes;
use anyhow::{Context, Result};

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
        let input = rpassword::prompt_password("Password: ").context("Unable to read password")?;
        input.as_bytes().to_vec()
    })
}
