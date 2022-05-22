use anyhow::{Context, Result};
use global::{BenchMode, CipherType, HashMode, Parameters, PasswordMode, SkipMode, BLOCK_SIZE};
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

            let hash_mode = if sub_matches.is_present("hash") {
                //specify to emit hash after operation
                HashMode::EmitHash
            } else {
                // default
                HashMode::HideHash
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

            let params = Parameters {
                hash_mode,
                skip,
                bench,
                password,
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
                    &params,
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
                    &params,
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

            let hash_mode = if sub_matches.is_present("hash") {
                //specify to emit hash after operation
                HashMode::EmitHash
            } else {
                // default
                HashMode::HideHash
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

            let params = Parameters {
                hash_mode,
                skip,
                bench,
                password,
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
                    &params,
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
                    &params,
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
        Some(("hash", sub_matches)) => {
            let file_name = sub_matches
                .value_of("input")
                .context("No input file provided")?;
            let file_size =
                std::fs::metadata(file_name).context("Unable to read metadata for x")?; // CHANGE THIS TO WITH CONTEXT

            if sub_matches.is_present("memory") {
                hashing::hash_memory(file_name)?;
            } else if file_size.len()
                <= BLOCK_SIZE
                    .try_into()
                    .context("Unable to parse stream block size as u64")?
            {
                println!("Input file size is less than the stream block size - redirecting to memory mode");
                hashing::hash_memory(file_name)?;
            } else {
                hashing::hash_stream(file_name)?;
            }
        }
        _ => (),
    }
    Ok(())
}
