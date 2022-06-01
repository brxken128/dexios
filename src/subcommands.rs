use anyhow::Result;
use clap::ArgMatches;

// this is called from main.rs
// it gets params and sends them to the appropriate functions

use crate::global::parameters::{
    decrypt_additional_params, encrypt_additional_params, erase_params, get_param,
    parameter_handler,
};

pub fn encrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;
    let algorithm = encrypt_additional_params(sub_matches)?;

    // stream mode is the default - it'll redirect to memory mode if the file is too small
    crate::encrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &params,
        algorithm,
    )
}

pub fn decrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;
    let header = decrypt_additional_params(sub_matches)?;

    // stream decrypt is the default as it will redirect to memory mode if the header says so
    crate::decrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &header,
        &params,
    )
}

pub fn erase(sub_matches: &ArgMatches) -> Result<()> {
    let passes = erase_params(sub_matches)?;

    crate::erase::secure_erase(&get_param("input", sub_matches)?, passes)
}