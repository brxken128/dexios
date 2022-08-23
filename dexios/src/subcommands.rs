use anyhow::Result;
use clap::ArgMatches;

// this is called from main.rs
// it gets params and sends them to the appropriate functions

use crate::global::{
    parameters::{
        algorithm, erase_params, forcemode, get_param, get_params, key_manipulation_params,
        pack_params, parameter_handler,
    },
    states::{Key, KeyParams},
};

pub mod decrypt;
pub mod encrypt;
pub mod erase;
pub mod hashing;
pub mod header;
pub mod key;
pub mod pack;
pub mod unpack;

pub fn encrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;
    let algorithm = algorithm(sub_matches);

    // stream mode is the only mode to encrypt (v8.5.0+)
    encrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &params,
        algorithm,
    )
}

pub fn decrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;

    // stream decrypt is the default as it will redirect to memory mode if the header says so (for backwards-compat)
    decrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &params,
    )
}

pub fn erase(sub_matches: &ArgMatches) -> Result<()> {
    let (passes, force) = erase_params(sub_matches)?;

    erase::secure_erase(&get_param("input", sub_matches)?, passes, force)
}

pub fn pack(sub_matches: &ArgMatches) -> Result<()> {
    let (crypto_params, pack_params) = pack_params(sub_matches)?;
    let algorithm = algorithm(sub_matches);

    pack::execute(&pack::Request {
        input_file: &get_params("input", sub_matches)?,
        output_file: &get_param("output", sub_matches)?,
        pack_params,
        crypto_params,
        algorithm,
    })
}

pub fn unpack(sub_matches: &ArgMatches) -> Result<()> {
    use super::global::states::PrintMode;

    let crypto_params = parameter_handler(sub_matches)?;

    let print_mode = if sub_matches.is_present("verbose") {
        PrintMode::Verbose
    } else {
        PrintMode::Quiet
    };

    unpack::unpack(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        print_mode,
        crypto_params,
    )
}

pub fn hash_stream(sub_matches: &ArgMatches) -> Result<()> {
    let files: Vec<String> = if sub_matches.is_present("input") {
        let list: Vec<&str> = sub_matches.values_of("input").unwrap().collect();
        list.iter().map(std::string::ToString::to_string).collect()
    } else {
        Vec::new()
    };

    hashing::hash_stream(&files)
}

pub fn header_dump(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_dump = sub_matches.subcommand_matches("dump").unwrap();
    let force = forcemode(sub_matches_dump);

    header::dump(
        &get_param("input", sub_matches_dump)?,
        &get_param("output", sub_matches_dump)?,
        force,
    )
}

pub fn header_restore(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_restore = sub_matches.subcommand_matches("restore").unwrap();

    header::restore(
        &get_param("input", sub_matches_restore)?,
        &get_param("output", sub_matches_restore)?,
    )
}

pub fn header_strip(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_strip = sub_matches.subcommand_matches("strip").unwrap();

    header::strip(&get_param("input", sub_matches_strip)?)
}

pub fn header_details(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_details = sub_matches.subcommand_matches("details").unwrap();

    header::details(&get_param("input", sub_matches_details)?)
}

pub fn key_change(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_change_key = sub_matches.subcommand_matches("change").unwrap();

    let params = key_manipulation_params(sub_matches_change_key)?;

    key::change(
        &get_param("input", sub_matches_change_key)?,
        &params,
    )
}

pub fn key_add(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_add_key = sub_matches.subcommand_matches("add").unwrap();

    let params = key_manipulation_params(sub_matches_add_key)?;

    key::add(
        &get_param("input", sub_matches_add_key)?,
        &params,
    )
}

pub fn key_del(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_del_key = sub_matches.subcommand_matches("del").unwrap();
    let key = Key::init(sub_matches_del_key, &KeyParams::default(), "keyfile")?;

    key::delete(&get_param("input", sub_matches_del_key)?, &key)
}
