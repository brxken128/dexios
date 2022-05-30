use std::io::stdin;
use std::io::stdout;
use std::io::Write;

use crate::file::get_bytes;
use crate::global::enums::HeaderVersion;
use crate::global::enums::KeyFile;
use crate::global::enums::PasswordMode;
use crate::global::SALT_LEN;
use crate::secret::Secret;
use anyhow::{Context, Result};
use argon2::Argon2;
use argon2::Params;
use paris::info;
use paris::warn;
use rand::prelude::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use std::result::Result::Ok;
use zeroize::Zeroize;

#[cfg(target_family = "unix")]
use termion::input::TermRead;

#[cfg(target_family = "windows")]
use std::io::BufRead;

// this generates a salt for password hashing
pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt: [u8; SALT_LEN] = [0; SALT_LEN];
    StdRng::from_entropy().fill_bytes(&mut salt);
    salt
}

// this handles argon2 hashing with the provided key
// it returns the key hashed with a specified salt
// it also ensures that raw_key is zeroed out
pub fn argon2_hash(
    raw_key: Secret<Vec<u8>>,
    salt: &[u8; SALT_LEN],
    version: &HeaderVersion,
) -> Result<Secret<[u8; 32]>> {
    let mut key = [0u8; 32];

    let params = match version {
        HeaderVersion::V1 => {
            // 8192KiB of memory, 8 iterations, 4 levels of parallelism
            let params = Params::new(8192, 8, 4, Some(Params::DEFAULT_OUTPUT_LEN));
            match params {
                std::result::Result::Ok(parameters) => parameters,
                Err(_) => return Err(anyhow::anyhow!("Error initialising argon2id parameters")),
            }
        }
        HeaderVersion::V2 => {
            let mem = 32768; // 32KiB - uses about 36MiB of memory
            let params = Params::new(mem, 12, 4, Some(Params::DEFAULT_OUTPUT_LEN));
            match params {
                std::result::Result::Ok(parameters) => parameters,
                Err(_) => return Err(anyhow::anyhow!("Error initialising argon2id parameters")),
            }
        }
    };

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let result = argon2.hash_password_into(raw_key.expose(), salt, &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(anyhow::anyhow!(
            "Error while hashing your password with argon2id"
        ));
    }

    Ok(Secret::new(key))
}

// this function interacts with stdin and stdout to hide password input
// it uses termion's `read_passwd` function for terminal manipulation
#[cfg(target_family = "unix")]
fn read_password_from_stdin_unix(prompt: &str) -> Result<String> {
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    stdout
        .write_all(prompt.as_bytes())
        .context("Unable to write to stdout")?;
    stdout.flush().context("Unable to flush stdout")?;

    if let Ok(Some(password)) = stdin.read_passwd(&mut stdout) {
        stdout
            .write_all("\n".as_bytes())
            .context("Unable to write to stdout")?;
        Ok(password)
    } else {
        stdout
            .write_all("\n".as_bytes())
            .context("Unable to write to stdout")?;
        Err(anyhow::anyhow!("Error reading password from terminal"))
    }
}

#[cfg(target_family = "windows")]
fn read_password_from_stdin_windows(prompt: &str) -> Result<String> {
    let mut stdout = stdout();
    let stdin = stdin();

    let mut password = String::new();

    stdout
        .write_all(prompt.as_bytes())
        .context("Unable to write to stdout")?;
    stdout.flush().context("Unable to flush stdout")?;

    if BufRead::read_line(&mut stdin.lock(), &mut password).is_ok() {
        Ok(password.trim_end().to_string())
    } else {
        Err(anyhow::anyhow!("Error reading password from terminal"))
    }
}

// this interactively gets the user's password from the terminal
// it takes the password twice, compares, and returns the bytes
fn get_password(validation: bool) -> Result<Secret<Vec<u8>>> {
    Ok(loop {
        #[cfg(target_family = "unix")]
        let input =
            read_password_from_stdin_unix("Password: ").context("Unable to read password")?;
        #[cfg(target_family = "windows")]
        let input =
            read_password_from_stdin_windows("Password: ").context("Unable to read password")?;
        if !validation {
            return Ok(Secret::new(input.into_bytes()));
        }

        #[cfg(target_family = "unix")]
        let mut input_validation = read_password_from_stdin_unix("Password (for validation): ")
            .context("Unable to read password")?;
        #[cfg(target_family = "windows")]
        let mut input_validation = read_password_from_stdin_windows("Password (for validation): ")
            .context("Unable to read password")?;

        if input == input_validation && !input.is_empty() {
            input_validation.zeroize();
            break Secret::new(input.into_bytes());
        } else if input.is_empty() {
            warn!("Password cannot be empty, please try again.");
        } else {
            warn!("The passwords aren't the same, please try again.");
        }
    })
}

// this takes in the keyfile string - if if's not empty, get those bytes
// next, if the env var DEXIOS_KEY is set, retrieve the value
// if neither of the above are true, ask the user for their specified key
// if validation is true, call get_password_with_validation and require it be entered twice
// if not, just get the key once
// it also checks that the key is not empty
#[allow(clippy::module_name_repetitions)] // possibly temporary - need a way to handle this (maybe key::handler?)
pub fn get_secret(
    keyfile: &KeyFile,
    validation: bool,
    password_mode: PasswordMode,
) -> Result<Secret<Vec<u8>>> {
    let key = if keyfile != &KeyFile::None {
        let keyfile_name = keyfile.get_contents()?;
        info!("Reading key from {}", keyfile_name);
        get_bytes(&keyfile_name)?
    } else if std::env::var("DEXIOS_KEY").is_ok()
        && password_mode == PasswordMode::NormalKeySourcePriority
    {
        info!("Reading key from DEXIOS_KEY environment variable");
        Secret::new(
            std::env::var("DEXIOS_KEY")
                .context("Unable to read DEXIOS_KEY from environment variable")?
                .into_bytes(),
        )
    } else {
        get_password(validation)?
    };
    if key.expose().is_empty() {
        Err(anyhow::anyhow!("The specified key is empty!"))
    } else {
        Ok(key)
    }
}
