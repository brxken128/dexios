use crate::global::{
    BenchMode, CipherType, DexiosMode, EraseMode, HashMode, HeaderType, Parameters, PasswordMode,
    SkipMode,
};
use anyhow::{Context, Result};
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

    let cipher_type = if sub_matches.is_present("gcm") {
        // specify gcm manually
        CipherType::AesGcm
    } else {
        // default
        CipherType::XChaCha20Poly1305
    };

    Ok((
        keyfile,
        Parameters {
            hash_mode,
            skip,
            bench,
            password,
            erase,
            cipher_type,
        },
    ))
}

pub fn header_type_handler(sub_matches: &ArgMatches) -> Result<HeaderType> {
    if !sub_matches.is_present("memory") && !sub_matches.is_present("stream") {
        return Err(anyhow::anyhow!(
            "You need to specify if the file was created in memory or stream mode."
        ));
    }

    if !sub_matches.is_present("xchacha") && !sub_matches.is_present("gcm") {
        return Err(anyhow::anyhow!(
            "You need to specify if the file was created using XChaCha20-Poly1305 or AES-256-GCM."
        ));
    }

    let dexios_mode = if sub_matches.is_present("memory") {
        DexiosMode::MemoryMode
    } else {
        DexiosMode::StreamMode
    };

    let cipher_type = if sub_matches.is_present("gcm") {
        CipherType::AesGcm
    } else {
        CipherType::XChaCha20Poly1305
    };

    Ok(HeaderType {
        dexios_mode,
        cipher_type,
    })
}
