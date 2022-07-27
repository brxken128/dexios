// TODO(brxken128): give this file a better name
use crate::global::states::Key;
use crate::global::states::PasswordState;
use anyhow::{Context, Result};
use dexios_core::header::HashingAlgorithm;
use domain::key_manipulation::RequestType;
use std::cell::RefCell;
use std::fs::OpenOptions;

use crate::{info, success};

pub fn manipulate_key(
    input: &str,
    key_old: &Key,
    key_new: Option<&Key>,
    request_type: RequestType,
) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {}", input))?,
    );

    match key_old {
        Key::User => info!("Please enter your old key below"),
        Key::Keyfile(_) => info!("Reading your old keyfile"),
        _ => (),
    }
    let raw_key_old = key_old.get_secret(&PasswordState::Direct)?;

    let raw_key_new = match request_type {
        RequestType::Add | RequestType::Change => {
            let key_new = key_new.context("No new key provided when it should've been")?;
            match key_new {
                Key::Generate => info!("Generating a new key"),
                Key::User => info!("Please enter your new key below"),
                Key::Keyfile(_) => info!("Reading your new keyfile"),
                Key::Env => (),
            }
            Some(key_new.get_secret(&PasswordState::Validate)?)
        }
        RequestType::Delete => None,
    };

    domain::key_manipulation::execute(domain::key_manipulation::Request {
        request_type,
        handle: &input_file,
        hash_algorithm: Some(HashingAlgorithm::Blake3Balloon(5)),
        raw_key_old,
        raw_key_new,
    })?;

    match request_type {
        RequestType::Add => success!("Key successfully added!"),
        RequestType::Change => success!("Key successfully changed!"),
        RequestType::Delete => success!("Key successfully deleted!"),
    }

    Ok(())
}
