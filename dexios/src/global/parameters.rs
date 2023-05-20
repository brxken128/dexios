// this file handles getting parameters from clap's ArgMatches
// it returns information (e.g. CryptoParams) to functions that require it

use crate::global::states::{EraseMode, EraseSourceDir, ForceMode, HashMode, HeaderLocation};
use crate::global::structs::CryptoParams;
use crate::global::structs::PackParams;
use crate::warn;
use anyhow::{Context, Result};
use clap::ArgMatches;
use core::header::{HashingAlgorithm, ARGON2ID_LATEST, BLAKE3BALLOON_LATEST};
use core::primitives::Algorithm;

use super::states::{Compression, DirectoryMode, Key, KeyParams, PrintMode};
use super::structs::KeyManipulationParams;

pub fn get_params(name: &str, sub_matches: &ArgMatches) -> Result<Vec<String>> {
    let values = sub_matches
        .get_many::<String>(name)
        .with_context(|| format!("No {name} provided"))?
        .map(String::from)
        .collect();
    Ok(values)
}

pub fn get_param(name: &str, sub_matches: &ArgMatches) -> Result<String> {
    let value = sub_matches
        .value_of(name)
        .with_context(|| format!("No {} provided", name))?
        .to_string();
    Ok(value)
}

// the main parameter handler for encrypt/decrypt
pub fn parameter_handler(sub_matches: &ArgMatches) -> Result<CryptoParams> {
    let key = Key::init(sub_matches, &KeyParams::default(), "keyfile")?;

    let hash_mode = if sub_matches.is_present("hash") {
        //specify to emit hash after operation
        HashMode::CalculateHash
    } else {
        // default
        HashMode::NoHash
    };

    let force = forcemode(sub_matches);

    let erase = if sub_matches.is_present("erase") {
        let result = sub_matches
            .value_of("erase")
            .context("No amount of passes specified")?
            .parse();

        if let Ok(value) = result {
            EraseMode::EraseFile(value)
        } else {
            warn!("No amount of passes provided - using the default.");
            EraseMode::EraseFile(1)
        }
    } else {
        EraseMode::IgnoreFile
    };

    let header_location = if sub_matches.is_present("header") {
        HeaderLocation::Detached(
            sub_matches
                .value_of("header")
                .context("No header/invalid text provided")?
                .to_string(),
        )
    } else {
        HeaderLocation::Embedded
    };

    let hashing_algorithm = hashing_algorithm(sub_matches);

    Ok(CryptoParams {
        hash_mode,
        force,
        erase,
        key,
        header_location,
        hashing_algorithm,
    })
}

pub fn hashing_algorithm(sub_matches: &ArgMatches) -> HashingAlgorithm {
    if sub_matches.is_present("argon") {
        HashingAlgorithm::Argon2id(ARGON2ID_LATEST)
    } else {
        HashingAlgorithm::Blake3Balloon(BLAKE3BALLOON_LATEST)
    }
}

// gets the algorithm, primarily for encrypt functions
pub fn algorithm(sub_matches: &ArgMatches) -> Algorithm {
    if sub_matches.is_present("aes") {
        Algorithm::Aes256Gcm
    } else {
        Algorithm::XChaCha20Poly1305
    }
}

pub fn erase_params(sub_matches: &ArgMatches) -> Result<(i32, ForceMode)> {
    let passes = if sub_matches.is_present("passes") {
        let result = sub_matches
            .value_of("passes")
            .context("No amount of passes specified")?
            .parse::<i32>();
        if let Ok(value) = result {
            value
        } else {
            warn!("Unable to read number of passes provided - using the default.");
            1
        }
    } else {
        warn!("Number of passes not provided - using the default.");
        1
    };

    let force = forcemode(sub_matches);

    Ok((passes, force))
}

pub fn pack_params(sub_matches: &ArgMatches) -> Result<(CryptoParams, PackParams)> {
    let key = Key::init(sub_matches, &KeyParams::default(), "keyfile")?;

    let hash_mode = if sub_matches.is_present("hash") {
        //specify to emit hash after operation
        HashMode::CalculateHash
    } else {
        // default
        HashMode::NoHash
    };

    let force = forcemode(sub_matches);

    let erase = EraseMode::IgnoreFile;

    let header_location = if sub_matches.is_present("header") {
        HeaderLocation::Detached(
            sub_matches
                .value_of("header")
                .context("No header/invalid text provided")?
                .to_string(),
        )
    } else {
        HeaderLocation::Embedded
    };

    let hashing_algorithm = hashing_algorithm(sub_matches);

    let crypto_params = CryptoParams {
        hash_mode,
        force,
        erase,
        key,
        header_location,
        hashing_algorithm,
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

pub fn forcemode(sub_matches: &ArgMatches) -> ForceMode {
    if sub_matches.is_present("force") {
        ForceMode::Force
    } else {
        ForceMode::Prompt
    }
}

pub fn key_manipulation_params(sub_matches: &ArgMatches) -> Result<KeyManipulationParams> {
    let key_old = Key::init(
        sub_matches,
        &KeyParams {
            user: true,
            env: false,
            autogenerate: false,
            keyfile: true,
        },
        "keyfile-old",
    )?;

    let key_new = Key::init(
        sub_matches,
        &KeyParams {
            user: true,
            env: false,
            autogenerate: true,
            keyfile: true,
        },
        "keyfile-new",
    )?;

    let hashing_algorithm = hashing_algorithm(sub_matches);

    Ok(KeyManipulationParams {
        key_old,
        key_new,
        hashing_algorithm,
    })
}
