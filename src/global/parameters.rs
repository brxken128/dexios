// this file contains most of the enum's, structs and associated functions used throughout dexios
// it includes all of the parameters passed to cryptographic functions
// it also contains enums/structs relating to headers
// this file is long, but necessary

use crate::global::enums::{
    Algorithm, BenchMode, DirectoryMode, EraseMode, HashMode, HeaderFile, HiddenFilesMode, KeyFile,
    PasswordMode, PrintMode, SkipMode,
};
use crate::global::structs::{CryptoParams, PackMode};
use anyhow::{Context, Result};
use clap::ArgMatches;

use super::ALGORITHMS;

pub fn get_param(name: &str, sub_matches: &ArgMatches) -> Result<String> {
    let value = sub_matches
        .value_of(name)
        .with_context(|| format!("No {} provided", name))?
        .to_string();
    Ok(value)
}

pub fn parameter_handler(sub_matches: &ArgMatches) -> Result<CryptoParams> {
    let keyfile = if sub_matches.is_present("keyfile") {
        KeyFile::Some(
            sub_matches
                .value_of("keyfile")
                .context("No keyfile/invalid text provided")?
                .to_string(),
        )
    } else {
        KeyFile::None
    };

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

    let erase = if sub_matches.is_present("erase") {
        let result = sub_matches
            .value_of("erase")
            .context("No amount of passes specified")?
            .parse();

        let passes = if let Ok(value) = result {
            value
        } else {
            println!("Unable to read number of passes provided - using the default.");
            16
        };
        EraseMode::EraseFile(passes)
    } else {
        EraseMode::IgnoreFile(0)
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

    Ok(CryptoParams {
        hash_mode,
        skip,
        bench,
        password,
        erase,
        keyfile,
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

pub fn decrypt_additional_params(sub_matches: &ArgMatches) -> Result<HeaderFile> {
    let header = if sub_matches.is_present("header") {
        HeaderFile::Some(
            sub_matches
                .value_of("header")
                .context("No header/invalid text provided")?
                .to_string(),
        )
    } else {
        HeaderFile::None
    };

    Ok(header)
}

pub fn erase_additional_params(sub_matches: &ArgMatches) -> Result<i32> {
    let passes = if sub_matches.is_present("passes") {
        let result = sub_matches
            .value_of("passes")
            .context("No amount of passes specified")?
            .parse::<i32>();
        if let Ok(value) = result {
            value
        } else {
            println!("Unable to read number of passes provided - using the default.");
            16
        }
    } else {
        println!("Number of passes not provided - using the default.");
        16
    };

    Ok(passes)
}

pub fn pack_additional_params(sub_matches: &ArgMatches) -> Result<PackMode> {
    let dir_mode = if sub_matches.is_present("recursive") {
        DirectoryMode::Recursive
    } else {
        DirectoryMode::Singular
    };

    let hidden = if sub_matches.is_present("hidden") {
        HiddenFilesMode::Include
    } else {
        HiddenFilesMode::Exclude
    };

    let compression_level = if sub_matches.is_present("level") {
        let result = sub_matches
            .value_of("level")
            .context("No compression level specified")?
            .parse();

        if let Ok(value) = result {
            if (0..=9).contains(&value) {
                value
            } else {
                println!("Compression level is out of specified bounds - using the default (6).");
                6
            }
        } else {
            println!("Unable to read compression level provided - using the default (6).");
            6
        }
    } else {
        6
    };

    let excluded: Vec<String> = if sub_matches.is_present("exclude") {
        let list: Vec<&str> = sub_matches.values_of("exclude").unwrap().collect();
        list.iter().map(std::string::ToString::to_string).collect()
    // this fixes 'static lifetime issues
    } else {
        Vec::new()
    };

    let print_mode = if sub_matches.is_present("verbose") {
        PrintMode::Verbose
    } else {
        PrintMode::Quiet
    };

    let pack_params = PackMode {
        compression_level,
        dir_mode,
        exclude: excluded,
        hidden,
        print_mode,
    };

    Ok(pack_params)
}

pub fn unpack_additional_params(sub_matches: &ArgMatches) -> PrintMode {
    if sub_matches.is_present("verbose") {
        PrintMode::Verbose
    } else {
        PrintMode::Quiet
    }
}
