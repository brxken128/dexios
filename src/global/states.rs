// this file contains enums found all around the codebase
// they act as toggles for certain features, so they can be
// enabled if selected by the user
// some enums are used purely by dexios to handle things (e.g. detached header files)

use anyhow::{Context, Result};
use dexios_core::protected::Protected;
use paris::warn;

use crate::{
    file::get_bytes,
    subcommands::key::{generate_passphrase, get_password},
};

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DirectoryMode {
    Singular,
    Recursive,
}

pub enum Compression {
    None,
    Zstd,
}

#[derive(PartialEq)]
pub enum HiddenFilesMode {
    Include,
    Exclude,
}

#[derive(PartialEq)]
pub enum EraseSourceDir {
    Erase,
    Retain,
}

#[derive(PartialEq)]
pub enum PrintMode {
    Verbose,
    Quiet,
}

#[derive(PartialEq, Clone, Copy)]
pub enum EraseMode {
    EraseFile(i32),
    IgnoreFile(i32),
}

#[derive(PartialEq, Clone, Copy)]
pub enum HashMode {
    CalculateHash,
    NoHash,
}

#[derive(PartialEq, Copy, Clone)]
pub enum SkipMode {
    ShowPrompts,
    HidePrompts,
}

#[derive(PartialEq, Copy, Clone)]
pub enum PasswordMode {
    ForceUserProvidedPassword,
    NormalKeySourcePriority,
}

#[derive(PartialEq)]
pub enum KeyFile {
    Some(String),
    None,
}

pub enum Key {
    Keyfile(String),
    Env,
    Generate,
    User,
}

#[derive(PartialEq)]
pub enum PasswordState {
    Validate,
    Direct, // maybe not the best name
}

impl Key {
    pub fn get_secret(&self, pass_state: &PasswordState) -> Result<Protected<Vec<u8>>> {
        let secret = match self {
            Key::Keyfile(path) => get_bytes(&path)?,
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
}

pub enum HeaderFile {
    Some(String),
    None,
}

impl EraseMode {
    pub fn get_passes(self) -> i32 {
        match self {
            EraseMode::EraseFile(passes) => passes,
            EraseMode::IgnoreFile(_) => 0,
        }
    }
}

impl KeyFile {
    pub fn get_inner(&self) -> Result<String> {
        match self {
            KeyFile::Some(data) => Ok(data.to_string()),
            KeyFile::None => Err(anyhow::anyhow!(
                "Tried using a keyfile when one wasn't provided"
            )), // should never happen
        }
    }

    pub fn is_present(&self) -> bool {
        match self {
            KeyFile::Some(_) => true,
            KeyFile::None => false,
        }
    }
}
