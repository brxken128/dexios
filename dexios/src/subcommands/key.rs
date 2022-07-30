// TODO(brxken128): give this file a better name
use crate::global::states::Key;
use crate::global::states::PasswordState;
use anyhow::{Context, Result};
use dexios_core::header::HashingAlgorithm;
use std::cell::RefCell;
use std::fs::OpenOptions;

use crate::info;

pub fn add(
    input: &str,
    key_old: &Key,
    key_new: &Key,
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

    match key_new {
        Key::Generate => info!("Generating a new key"),
        Key::User => info!("Please enter your new key below"),
        Key::Keyfile(_) => info!("Reading your new keyfile"),
        Key::Env => (),
    }

    let raw_key_new = key_new.get_secret(&PasswordState::Validate)?;

    domain::key::add::execute(domain::key::add::Request {
        handle: &input_file,
        hash_algorithm: HashingAlgorithm::Blake3Balloon(5),
        raw_key_old,
        raw_key_new,
    })?;

    Ok(())
}

pub fn change(
    input: &str,
    key_old: &Key,
    key_new: &Key,
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
    match key_new {
        Key::Generate => info!("Generating a new key"),
        Key::User => info!("Please enter your new key below"),
        Key::Keyfile(_) => info!("Reading your new keyfile"),
        Key::Env => (),
    }

    let raw_key_new = key_new.get_secret(&PasswordState::Validate)?;

    domain::key::change::execute(domain::key::change::Request {
        handle: &input_file,
        hash_algorithm: HashingAlgorithm::Blake3Balloon(5),
        raw_key_old,
        raw_key_new,
    })?;

    Ok(())
}

pub fn delete(
    input: &str,
    key_old: &Key,
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


    domain::key::delete::execute(domain::key::delete::Request {
        handle: &input_file,
        raw_key_old,
    })?;

    Ok(())
}
