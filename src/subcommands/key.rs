use std::io::{stdin, stdout, Write};

use anyhow::{Context, Result};
use dexios_core::protected::Protected;
use dexios_core::Zeroize;
use paris::{info, warn};
use rand::{prelude::StdRng, Rng, SeedableRng};

use crate::{
    file::get_bytes,
    global::states::{KeyFile, PasswordMode, PasswordState},
};

// this function interacts with stdin and stdout to hide password input
// it uses termion's `read_passwd` function for terminal manipulation
#[cfg(target_family = "unix")]
fn read_password_from_stdin_unix(prompt: &str) -> Result<String> {
    use termion::input::TermRead;

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
    use std::io::BufRead;
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
pub fn get_password(pass_state: &PasswordState) -> Result<Protected<Vec<u8>>> {
    Ok(loop {
        #[cfg(target_family = "unix")]
        let input =
            read_password_from_stdin_unix("Password: ").context("Unable to read password")?;
        #[cfg(target_family = "windows")]
        let input =
            read_password_from_stdin_windows("Password: ").context("Unable to read password")?;
        if pass_state == &PasswordState::Direct {
            return Ok(Protected::new(input.into_bytes()));
        }

        #[cfg(target_family = "unix")]
        let mut input_validation = read_password_from_stdin_unix("Password (for validation): ")
            .context("Unable to read password")?;
        #[cfg(target_family = "windows")]
        let mut input_validation = read_password_from_stdin_windows("Password (for validation): ")
            .context("Unable to read password")?;

        if input == input_validation && !input.is_empty() {
            input_validation.zeroize();
            break Protected::new(input.into_bytes());
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
    pass_state: &PasswordState,
    password_mode: PasswordMode,
) -> Result<Protected<Vec<u8>>> {
    let key = if keyfile != &KeyFile::None {
        let keyfile_name = keyfile.get_inner()?;
        info!("Reading key from {}", keyfile_name);
        get_bytes(&keyfile_name)?
    } else if std::env::var("DEXIOS_KEY").is_ok()
        && password_mode == PasswordMode::NormalKeySourcePriority
    {
        info!("Reading key from DEXIOS_KEY environment variable");
        Protected::new(
            std::env::var("DEXIOS_KEY")
                .context("Unable to read DEXIOS_KEY from environment variable")?
                .into_bytes(),
        )
    } else {
        get_password(pass_state)?
    };
    if key.expose().is_empty() {
        Err(anyhow::anyhow!("The specified key is empty!"))
    } else {
        Ok(key)
    }
}

pub fn generate_passphrase() -> Protected<String> {
    let collection = include_str!("wordlist.lst");
    let words = collection.split('\n').collect::<Vec<&str>>();

    let mut passphrase = String::new();

    for _ in 0..3 {
        let index = StdRng::from_entropy().gen_range(0..=words.len());
        passphrase.push_str(words[index]);
        passphrase.push('-');
    }

    for _ in 0..5 {
        let number = StdRng::from_entropy().gen_range(0..=9);
        passphrase.push(number.into());
    }

    Protected::new(passphrase)
}
