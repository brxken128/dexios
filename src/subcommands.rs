use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::global::parameters::{parameter_handler, encrypt_additional_params, decrypt_additional_params};

pub fn encrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;
    let algorithm = encrypt_additional_params(sub_matches)?;

    // stream mode is the default - it'll redirect to memory mode if the file is too small
    crate::encrypt::stream_mode(
        sub_matches
            .value_of("input")
            .context("No input file/invalid text provided")?,
        sub_matches
            .value_of("output")
            .context("No output file/invalid text provided")?,
        &params,
        algorithm,
    )
}

pub fn decrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;
    let header = decrypt_additional_params(sub_matches)?;

    // stream decrypt is the default as it will redirect to memory mode if the header says so
    crate::decrypt::stream_mode(
        sub_matches
            .value_of("input")
            .context("No input file/invalid text provided")?,
        sub_matches
            .value_of("output")
            .context("No output file/invalid text provided")?,
        &header,
        &params,
    )
}