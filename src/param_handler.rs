use anyhow::{Result, Context};
use crate::global::{BenchMode, CipherType, HashMode, Parameters, PasswordMode, SkipMode, BLOCK_SIZE};
use clap::ArgMatches;

pub fn param_handler(sub_matches: &ArgMatches) -> Result<(&str, Parameters)> {
    let mut keyfile = "";
    if sub_matches.is_present("keyfile") {
        keyfile = sub_matches
            .value_of("keyfile")
            .context("No keyfile/invalid text provided")?;
    }

    let hash_mode = if sub_matches.is_present("hash") {
        //specify to emit hash after operation
        HashMode::CalculateHash
    } else {
        // default
        HashMode::NoHash
    };

    let skip = if sub_matches.is_present("skip") {
        //specify to hide promps during operation
        SkipMode::HidePrompts
    } else {
        // default
        SkipMode::ShowPrompts
    };

    let bench = if sub_matches.is_present("bench") {
        //specify to not write to filesystem, for benchmarking and saving wear on hardware
        BenchMode::BenchmarkInMemory
    } else {
        // default
        BenchMode::WriteToFilesystem
    };

    let password = if sub_matches.is_present("password") {
        //Overwrite, so the user provided password is used and ignore environment supplied one?!
        PasswordMode::ForceUserProvidedPassword
    } else {
        // default
        PasswordMode::NormalKeySourcePriority
    };

    let cipher_type = if sub_matches.is_present("gcm") {
        // specify gcm manually
        CipherType::AesGcm
    } else {
        // default
        CipherType::XChaCha20Poly1305
    };

    Ok((keyfile, Parameters {
        hash_mode,
        skip,
        bench,
        password,
        cipher_type,
    }))
}