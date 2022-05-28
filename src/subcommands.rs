use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::global::parameters::{
    decrypt_additional_params, encrypt_additional_params, erase_additional_params, get_param,
    pack_additional_params, parameter_handler, unpack_additional_params,
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
    let passes = erase_additional_params(sub_matches)?;

    crate::erase::secure_erase(
        sub_matches
            .value_of("input")
            .context("No input file/invalid text provided")?,
        passes,
    )
}

pub fn pack(sub_matches: &ArgMatches) -> Result<()> {
    let pack_params = pack_additional_params(sub_matches)?;
    let sub_matches_encrypt = sub_matches.subcommand_matches("encrypt").unwrap();
    let params = parameter_handler(sub_matches_encrypt)?;
    let algorithm = encrypt_additional_params(sub_matches_encrypt)?;

    crate::pack::encrypt_directory(
        &get_param("input", sub_matches_encrypt)?,
        &get_param("output", sub_matches_encrypt)?,
        &pack_params,
        &params,
        algorithm,
    )
}

pub fn unpack(sub_matches: &ArgMatches) -> Result<()> {
    let print_mode = unpack_additional_params(sub_matches)?;

    let sub_matches_decrypt = sub_matches.subcommand_matches("decrypt").unwrap();
    let params = parameter_handler(sub_matches_decrypt)?;
    let header = decrypt_additional_params(sub_matches_decrypt)?;

    crate::pack::decrypt_directory(
        &get_param("input", sub_matches_decrypt)?,
        &get_param("output", sub_matches_decrypt)?,
        &header,
        &print_mode,
        &params,
    )
}
