// this file contains enums found all around the codebase
// they act as toggles for certain features, so they can be
// enabled if selected by the user

use anyhow::{Context, Result};
use clap::ArgMatches;
use core::protected::Protected;

use crate::cli::prompt::get_password;
use crate::warn;
use core::key::generate_passphrase;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DirectoryMode {
    Singular,
    Recursive,
}

pub enum Compression {
    None,
    Zstd,
}

#[derive(PartialEq, Eq)]
pub enum EraseSourceDir {
    Erase,
    Retain,
}

#[derive(PartialEq, Eq)]
pub enum PrintMode {
    Verbose,
    Quiet,
}

pub enum HeaderLocation {
    Embedded,
    Detached(String),
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum EraseMode {
    EraseFile(i32),
    IgnoreFile,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum HashMode {
    CalculateHash,
    NoHash,
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum ForceMode {
    Force,
    Prompt,
}

#[derive(PartialEq, Eq)]
pub enum Key {
    Keyfile(String),
    Env,
    Generate,
    User,
}

#[derive(PartialEq, Eq)]
pub enum PasswordState {
    Validate,
    Direct, // maybe not the best name
}

fn get_bytes<R: std::io::Read>(reader: &mut R) -> Result<Protected<Vec<u8>>> {
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .context("Unable to read data")?;
    Ok(Protected::new(data))
}

impl Key {
    // this handles getting the secret, and returning it
    // it relies on `parameters.rs`' handling and logic to determine which route to get the key
    // it can handle keyfiles, env variables, automatically generating and letting the user enter a key
    // it has a check for if the keyfile is empty or not
    pub fn get_secret(&self, pass_state: &PasswordState) -> Result<Protected<Vec<u8>>> {
        let secret = match self {
            Key::Keyfile(path) if path == "-" => {
                let mut reader = std::io::stdin();
                let secret = get_bytes(&mut reader)?;
                if secret.is_empty() {
                    return Err(anyhow::anyhow!("STDIN is empty"));
                }
                secret
            }
            Key::Keyfile(path) => {
                let mut reader = std::fs::File::open(path)
                    .with_context(|| format!("Unable to read file: {}", path))?;
                let secret = get_bytes(&mut reader)?;
                if secret.is_empty() {
                    return Err(anyhow::anyhow!(format!("Keyfile '{}' is empty", path)));
                }
                secret
            }
            Key::Env => Protected::new(
                std::env::var("DEXIOS_KEY")
                    .context("Unable to read DEXIOS_KEY from environment variable")?
                    .into_bytes(),
            ),
            Key::User => get_password(pass_state)?,
            Key::Generate => {
                let passphrase = generate_passphrase();
                warn!("Your generated passphrase is: {}", passphrase.expose());
                let key = Protected::new(passphrase.expose().clone().into_bytes());
                drop(passphrase);
                key
            }
        };

        if secret.expose().is_empty() {
            Err(anyhow::anyhow!("The specified key is empty!"))
        } else {
            Ok(secret)
        }
    }

    pub fn init(
        sub_matches: &ArgMatches,
        params: &KeyParams,
        keyfile_descriptor: &str,
    ) -> Result<Self> {
        let key = if sub_matches.is_present(keyfile_descriptor) && params.keyfile {
            Key::Keyfile(
                sub_matches
                    .value_of(keyfile_descriptor)
                    .context("No keyfile/invalid text provided")?
                    .to_string(),
            )
        } else if std::env::var("DEXIOS_KEY").is_ok() && params.env {
            Key::Env
        } else if let (Ok(true), true) = (
            sub_matches.try_contains_id("autogenerate"),
            params.autogenerate,
        ) {
            Key::Generate
        } else if params.user {
            Key::User
        } else {
            return Err(anyhow::anyhow!(
                "No key sources found with the parameters/arguments provided"
            ));
        };

        Ok(key)
    }
}

#[allow(clippy::struct_excessive_bools)]
pub struct KeyParams {
    pub user: bool,
    pub env: bool,
    pub autogenerate: bool,
    pub keyfile: bool,
}

impl KeyParams {
    pub fn default() -> Self {
        KeyParams {
            user: true,
            env: true,
            autogenerate: true,
            keyfile: true,
        }
    }
}
