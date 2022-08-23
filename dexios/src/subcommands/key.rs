// TODO(brxken128): give this file a better name
use crate::global::states::Key;
use crate::global::states::PasswordState;
use crate::global::structs::KeyManipulationParams;
use anyhow::{Context, Result};
use dcore::header::Header;
use dcore::header::HeaderVersion;
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Seek;

use crate::info;

pub fn add(input: &str, params: &KeyManipulationParams) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {}", input))?,
    );

    let (header, _) = Header::deserialize(&mut *input_file.borrow_mut())?;

    if header.header_type.version < HeaderVersion::V5 {
        return Err(anyhow::anyhow!(
            "This function is not supported on header versions below V5"
        ));
    }

    input_file
        .borrow_mut()
        .rewind()
        .context("Unable to rewind the reader")?;

    if params.key_old == Key::User {
        info!("Please enter your old key below");
    }

    let raw_key_old = params.key_old.get_secret(&PasswordState::Direct)?;

    if params.key_new == Key::User {
        info!("Please enter your new key below");
    }

    let raw_key_new = params.key_new.get_secret(&PasswordState::Validate)?;

    ddomain::key::add::execute(ddomain::key::add::Request {
        handle: &input_file,
        hash_algorithm: params.hashing_algorithm,
        raw_key_old,
        raw_key_new,
    })?;

    Ok(())
}

pub fn change(input: &str, params: &KeyManipulationParams) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {}", input))?,
    );

    let (header, _) = Header::deserialize(&mut *input_file.borrow_mut())?;

    if header.header_type.version < HeaderVersion::V5 {
        return Err(anyhow::anyhow!(
            "This function is not supported on header versions below V5"
        ));
    }

    input_file
        .borrow_mut()
        .rewind()
        .context("Unable to rewind the reader")?;

    if params.key_old == Key::User {
        info!("Please enter your old key below");
    }

    let raw_key_old = params.key_old.get_secret(&PasswordState::Direct)?;

    if params.key_new == Key::User {
        info!("Please enter your new key below");
    }

    let raw_key_new = params.key_new.get_secret(&PasswordState::Validate)?;

    ddomain::key::change::execute(ddomain::key::change::Request {
        handle: &input_file,
        hash_algorithm: params.hashing_algorithm,
        raw_key_old,
        raw_key_new,
    })?;

    Ok(())
}

pub fn delete(input: &str, key_old: &Key) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {}", input))?,
    );

    let (header, _) = Header::deserialize(&mut *input_file.borrow_mut())?;

    if header.header_type.version < HeaderVersion::V5 {
        return Err(anyhow::anyhow!(
            "This function is not supported on header versions below V5"
        ));
    }

    input_file
        .borrow_mut()
        .rewind()
        .context("Unable to rewind the reader")?;

    if key_old == &Key::User {
        info!("Please enter your old key below");
    }

    let raw_key_old = key_old.get_secret(&PasswordState::Direct)?;

    ddomain::key::delete::execute(ddomain::key::delete::Request {
        handle: &input_file,
        raw_key_old,
    })?;

    Ok(())
}
