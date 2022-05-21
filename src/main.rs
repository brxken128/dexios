use anyhow::{Context, Result};
use global::{CipherType, Parameters};
use std::result::Result::Ok;

mod cli;
mod decrypt;
mod encrypt;
mod erase;
mod file;
mod global;
mod hashing;
mod key;
mod prompt;

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let matches = cli::get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let mut keyfile = "";
            if sub_matches.is_present("keyfile") {
                keyfile = sub_matches
                    .value_of("keyfile")
                    .context("No keyfile/invalid text provided")?;
            }

            let cipher_type = if sub_matches.is_present("gcm") {
                // specify gcm manually
                CipherType::AesGcm
            } else {
                // default
                CipherType::XChaCha20Poly1305
            };

            let params = Parameters {
                hash_mode: sub_matches.is_present("hash"),
                skip: sub_matches.is_present("skip"),
                bench: sub_matches.is_present("bench"),
                password: sub_matches.is_present("password"),
                cipher_type,
            };

            let result = if sub_matches.is_present("memory") {
                encrypt::memory_mode(
                    sub_matches
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    sub_matches
                        .value_of("output")
                        .context("No output file/invalid text provided")?,
                    keyfile,
                    params,
                )
            } else {
                encrypt::stream_mode(
                    sub_matches
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    sub_matches
                        .value_of("output")
                        .context("No output file/invalid text provided")?,
                    keyfile,
                    params,
                )
            };

            if result.is_ok() && sub_matches.is_present("erase") {
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

                erase::secure_erase(
                    sub_matches
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    passes,
                )?;
            }

            return result;
        }
        Some(("decrypt", sub_matches)) => {
            let mut keyfile = "";
            if sub_matches.is_present("keyfile") {
                keyfile = sub_matches
                    .value_of("keyfile")
                    .context("No keyfile/invalid text provided")?;
            }

            let cipher_type = if sub_matches.is_present("gcm") {
                // specify gcm manually
                CipherType::AesGcm
            } else {
                // default
                CipherType::XChaCha20Poly1305
            };

            let params = Parameters {
                hash_mode: sub_matches.is_present("hash"),
                skip: sub_matches.is_present("skip"),
                bench: sub_matches.is_present("bench"),
                password: sub_matches.is_present("password"),
                cipher_type,
            };

            let result = if sub_matches.is_present("memory") {
                decrypt::memory_mode(
                    sub_matches
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    sub_matches
                        .value_of("output")
                        .context("No output file/invalid text provided")?,
                    keyfile,
                    params,
                )
            } else {
                decrypt::stream_mode(
                    sub_matches
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    sub_matches
                        .value_of("output")
                        .context("No output file/invalid text provided")?,
                    keyfile,
                    params,
                )
            };

            if result.is_ok() && sub_matches.is_present("erase") {
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

                erase::secure_erase(
                    sub_matches
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    passes,
                )?;
            }

            return result;
        }
        Some(("erase", sub_matches)) => {
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
            erase::secure_erase(
                sub_matches
                    .value_of("input")
                    .context("No input file/invalid text provided")?,
                passes,
            )?;
        }
        _ => (),
    }
    Ok(())
}
