// this file handles getting parameters from clap's ArgMatches
// it returns information (e.g. CryptoParams) to functions that require it

use crate::global::states::{EraseMode, EraseSourceDir, HashMode, HeaderLocation, SkipMode};
use crate::global::structs::CryptoParams;
use crate::global::structs::PackParams;
use anyhow::{Context, Result};
use clap::ArgMatches;
use dexios_core::primitives::Algorithm;
use paris::warn;

use dexios_core::primitives::ALGORITHMS;

use super::states::{Compression, DirectoryMode, Key, PrintMode};

pub fn get_param(name: &str, sub_matches: &ArgMatches) -> Result<String> {
    let value = sub_matches
        .value_of(name)
        .with_context(|| format!("No {} provided", name))?
        .to_string();
    Ok(value)
}

pub fn parameter_handler(sub_matches: &ArgMatches) -> Result<CryptoParams> {
    let key = if sub_matches.is_present("keyfile") {
        Key::Keyfile(
            sub_matches
                .value_of("keyfile")
                .context("No keyfile/invalid text provided")?
                .to_string(),
        )
    } else if std::env::var("DEXIOS_KEY").is_ok() {
        Key::Env
    } else if sub_matches.is_present("autogenerate") {
        Key::Generate
    } else {
        Key::User
    };

    let hash_mode = if sub_matches.is_present("hash") {
        //specify to emit hash after operation
        HashMode::CalculateHash
    } else {
        // default
        HashMode::NoHash
    };

    let skip = skipmode(sub_matches);

    let erase = if sub_matches.is_present("erase") {
        let result = sub_matches
            .value_of("erase")
            .context("No amount of passes specified")?
            .parse();

        let passes = if let Ok(value) = result {
            value
        } else {
            warn!("Unable to read number of passes provided - using the default.");
            2
        };
        EraseMode::EraseFile(passes)
    } else {
        EraseMode::IgnoreFile(0)
    };

    Ok(CryptoParams {
        hash_mode,
        skip,
        erase,
        key,
    })
}

pub fn encrypt_additional_params(sub_matches: &ArgMatches) -> Result<Algorithm> {
    let provided_aead: usize = if sub_matches.is_present("aead") {
        sub_matches
            .value_of("aead")
            .context("Error reading value of --aead")?
            .parse()
            .context(
                "Invalid AEAD selected! Use \"dexios list aead\" to see all possible values.",
            )? // add context here
    } else {
        1
    };

    if provided_aead < 1 || provided_aead > ALGORITHMS.len() {
        Err(anyhow::anyhow!(
            "Invalid AEAD selected! Use \"dexios list aead\" to see all possible values."
        ))
    } else {
        Ok(ALGORITHMS[provided_aead - 1]) // -1 to account for indexing starting at 0
    }
}

pub fn decrypt_additional_params(sub_matches: &ArgMatches) -> Result<HeaderLocation> {
    let header = if sub_matches.is_present("header") {
        HeaderLocation::Detached(
            sub_matches
                .value_of("header")
                .context("No header/invalid text provided")?
                .to_string(),
        )
    } else {
        HeaderLocation::Embedded
    };

    Ok(header)
}

pub fn erase_params(sub_matches: &ArgMatches) -> Result<i32> {
    let passes = if sub_matches.is_present("passes") {
        let result = sub_matches
            .value_of("passes")
            .context("No amount of passes specified")?
            .parse::<i32>();
        if let Ok(value) = result {
            value
        } else {
            warn!("Unable to read number of passes provided - using the default.");
            2
        }
    } else {
        warn!("Number of passes not provided - using the default.");
        2
    };

    Ok(passes)
}

pub fn pack_params(sub_matches: &ArgMatches) -> Result<(CryptoParams, PackParams)> {
    let key = if sub_matches.is_present("keyfile") {
        Key::Keyfile(
            sub_matches
                .value_of("keyfile")
                .context("No keyfile/invalid text provided")?
                .to_string(),
        )
    } else if std::env::var("DEXIOS_KEY").is_ok() {
        Key::Env
    } else if sub_matches.is_present("autogenerate") {
        Key::Generate
    } else {
        Key::User
    };

    let hash_mode = if sub_matches.is_present("hash") {
        //specify to emit hash after operation
        HashMode::CalculateHash
    } else {
        // default
        HashMode::NoHash
    };

    let skip = skipmode(sub_matches);

    let erase = EraseMode::IgnoreFile(0);

    let crypto_params = CryptoParams {
        hash_mode,
        skip,
        erase,
        key,
    };

    let print_mode = if sub_matches.is_present("verbose") {
        //specify to emit hash after operation
        PrintMode::Verbose
    } else {
        // default
        PrintMode::Quiet
    };

    let dir_mode = if sub_matches.is_present("recursive") {
        //specify to emit hash after operation
        DirectoryMode::Recursive
    } else {
        // default
        DirectoryMode::Singular
    };

    let erase_source = if sub_matches.is_present("erase") {
        EraseSourceDir::Erase
    } else {
        EraseSourceDir::Retain
    };

    let compression = if sub_matches.is_present("zstd") {
        Compression::Zstd
    } else {
        Compression::None
    };

    let pack_params = PackParams {
        dir_mode,
        print_mode,
        erase_source,
        compression,
    };

    Ok((crypto_params, pack_params))
}

pub fn skipmode(sub_matches: &ArgMatches) -> SkipMode {
    if sub_matches.is_present("skip") {
        SkipMode::HidePrompts
    } else {
        SkipMode::ShowPrompts
    }
}

pub fn key_update_params(sub_matches: &ArgMatches) -> Result<(Key, Key)> {
    let key_old = if sub_matches.is_present("keyfile-old") {
        Key::Keyfile(
            sub_matches
                .value_of("keyfile-old")
                .context("No keyfile/invalid text provided")?
                .to_string(),
        )
    } else {
        Key::User
    };

    let key_new = if sub_matches.is_present("keyfile-new") {
        Key::Keyfile(
            sub_matches
                .value_of("keyfile-new")
                .context("No keyfile/invalid text provided")?
                .to_string(),
        )
    } else if sub_matches.is_present("autogenerate") {
        Key::Generate
    } else {
        Key::User
    };

    Ok((key_old, key_new))
}
