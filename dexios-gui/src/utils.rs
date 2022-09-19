use crate::error::Error;
use crate::states::{Decrypt, Encrypt};
use core::protected::Protected;
use std::io::Read;

// TODO(brxken128): put this and subcommands/header.rs in domain
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

#[macro_export]
macro_rules! ui_ok {
    ($res:expr, $message:expr) => {
        match $res {
            Ok(v) => v,
            _ => return crate::utils::message_box($message),
        }
    };
}

pub fn message_box(description: &str) {
    rfd::MessageDialog::new()
        .set_title("Dexios")
        .set_description(description)
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

#[derive(PartialEq, Clone)]
pub enum Key {
    Keyfile,
    AutoGenerate,
    Password,
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Keyfile => write!(f, "Keyfile"),
            Key::Password => write!(f, "Password"),
            Key::AutoGenerate => write!(f, "Auto Generate"),
        }
    }
}

impl Key {
    pub fn get_value_for_encrypting(&self, params: &Encrypt) -> Result<Protected<Vec<u8>>, Error> {
        match self {
            Key::Password => {
                if params.password == params.password_validation {
                    Ok(Protected::new(params.password.clone().into_bytes()))
                } else {
                    Err(Error::PasswordsDontMatch)
                }
            }
            Key::AutoGenerate => Ok(Protected::new(
                params.autogenerated_passphrase.clone().into_bytes(),
            )),
            Key::Keyfile => {
                let mut reader = std::fs::File::open(params.keyfile_path.clone())
                    .map_err(|_| Error::KeyfileRead)?;
                let mut secret = Vec::new();
                reader
                    .read_to_end(&mut secret)
                    .map_err(|_| Error::KeyfileRead)?;
                Ok(Protected::new(secret))
            }
        }
    }

    pub fn get_value_for_decrypting(&self, params: &Decrypt) -> Result<Protected<Vec<u8>>, Error> {
        match self {
            Key::Password => Ok(Protected::new(params.password.clone().into_bytes())),
            Key::AutoGenerate => Err(Error::Unsupported),
            Key::Keyfile => {
                let mut reader = std::fs::File::open(params.keyfile_path.clone()).unwrap();
                let mut secret = Vec::new();
                reader.read_to_end(&mut secret).unwrap();
                Ok(Protected::new(secret))
            }
        }
    }
}
