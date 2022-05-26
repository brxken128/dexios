use std::io::Write;
use std::io::stdin;
use std::io::stdout;

use crate::file::get_bytes;
use crate::global::parameters::HeaderVersion;
use crate::global::parameters::KeyFile;
use crate::global::parameters::PasswordMode;
use crate::global::SALT_LEN;
use anyhow::{Context, Result};
use argon2::Argon2;
use argon2::Params;
use secrecy::ExposeSecret;
use secrecy::Secret;
use secrecy::SecretVec;
use secrecy::Zeroize;
use termion::input::TermRead;
use std::result::Result::Ok;

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
    };

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let result = argon2.hash_password_into(raw_key.expose_secret(), salt, &mut key);
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
fn read_password_from_stdin(prompt: &str) -> Result<String> {
    let mut stdout = stdout().lock();
    let mut stdin = stdin().lock();

    stdout.write_all(prompt.as_bytes()).context("Unable to write to stdout")?;
    stdout.flush().context("Unable to flush stdout")?;

    match stdin.read_passwd(&mut stdout) {
        Ok(Some(password)) => {
            stdout.write_all("\n".as_bytes()).context("Unable to write to stdout")?;
            Ok(password)
        },
        _ => {
            stdout.write_all("\n".as_bytes()).context("Unable to write to stdout")?;
            Err(anyhow::anyhow!("Error reading password from terminal"))
        }
    }
}

// this interactively gets the user's password from the terminal
// it takes the password twice, compares, and returns the bytes
fn get_password(validation: bool) -> Result<Secret<Vec<u8>>> {
    Ok(loop {
        let input = read_password_from_stdin("Password: ").context("Unable to read password")?;
        if !validation {
            return Ok(SecretVec::new(input.into_bytes()));
        }

        let mut input_validation = read_password_from_stdin("Password (for validation): ")
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
// it also checks that the key is not empty
#[allow(clippy::module_name_repetitions)] // possibly temporary - need a way to handle this (maybe key::handler?)
pub fn get_secret(
    keyfile: &KeyFile,
    validation: bool,
    password_mode: PasswordMode,
) -> Result<Secret<Vec<u8>>> {
    let key = if keyfile != &KeyFile::None {
        let keyfile_name = keyfile.get_contents()?;
        println!("Reading key from {}", keyfile_name);
        get_bytes(&keyfile_name)?
    } else if std::env::var("DEXIOS_KEY").is_ok()
        && password_mode == PasswordMode::NormalKeySourcePriority
    {
        println!("Reading key from DEXIOS_KEY environment variable");
        SecretVec::new(
            std::env::var("DEXIOS_KEY")
                .context("Unable to read DEXIOS_KEY from environment variable")?
                .into_bytes(),
        )
    } else {
        get_password(validation)?
    };
    if key.expose_secret().is_empty() {
        Err(anyhow::anyhow!("The specified key is empty!"))
    } else {
        Ok(key)
    }
}
