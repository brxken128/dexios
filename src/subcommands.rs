use anyhow::Result;
use clap::ArgMatches;

// this is called from main.rs
// it gets params and sends them to the appropriate functions

use crate::global::parameters::{
    decrypt_additional_params, encrypt_additional_params, erase_params, get_param, pack_params,
    parameter_handler,
};

pub mod decrypt;
pub mod encrypt;
pub mod erase;
pub mod hashing;
pub mod header;
pub mod key;
pub mod list;
pub mod pack;
pub mod prompt;
pub mod unpack;

pub fn encrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;
    let algorithm = encrypt_additional_params(sub_matches)?;

    // stream mode is the only mode to decrypt (v8.5.0+)
    encrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &params,
        algorithm,
    )
}

pub fn decrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;
    let header = decrypt_additional_params(sub_matches)?;

    // stream decrypt is the default as it will redirect to memory mode if the header says so (for backwards-compat)
    decrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &header,
        &params,
    )
}

pub fn erase(sub_matches: &ArgMatches) -> Result<()> {
    let passes = erase_params(sub_matches)?;

    erase::secure_erase(&get_param("input", sub_matches)?, passes)
}

pub fn pack(sub_matches: &ArgMatches) -> Result<()> {
    let (crypto_params, pack_params) = pack_params(sub_matches)?;
    let aead = encrypt_additional_params(sub_matches)?;

    pack::pack(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &pack_params,
        &crypto_params,
        aead,
    )
}

pub fn unpack(sub_matches: &ArgMatches) -> Result<()> {
    use super::global::states::PrintMode;

    let crypto_params = parameter_handler(sub_matches)?;
    let header = decrypt_additional_params(sub_matches)?;

    let print_mode = if sub_matches.is_present("verbose") {
        //specify to emit hash after operation
        PrintMode::Verbose
    } else {
        // default
        PrintMode::Quiet
    };

    unpack::unpack(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &header,
        &print_mode,
        &crypto_params,
    )
}
