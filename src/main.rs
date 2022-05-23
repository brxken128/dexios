use anyhow::{Context, Result};
use global::{DirectoryMode, BLOCK_SIZE};
use param_handler::param_handler;
use std::result::Result::Ok;

mod cli;
mod decrypt;
mod directory;
mod encrypt;
mod erase;
mod file;
mod global;
mod hashing;
mod key;
mod param_handler;
mod prompt;

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let matches = cli::get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let (keyfile, params) = param_handler(sub_matches)?;

            let result = if sub_matches.is_present("memory") {
                crate::encrypt::memory_mode(
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
                crate::encrypt::stream_mode(
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

            return result;
        }
        Some(("decrypt", sub_matches)) => {
            let (keyfile, params) = param_handler(sub_matches)?;

            let result = if sub_matches.is_present("memory") {
                crate::decrypt::memory_mode(
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
                crate::decrypt::stream_mode(
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
            let file_size = std::fs::metadata(file_name)
                .with_context(|| format!("Unable to get file metadata: {}", file_name))?;

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
        Some(("pack", sub_matches)) => match sub_matches.subcommand_name() {
            Some("encrypt") => {
                let mode = if sub_matches.is_present("recursive") {
                    DirectoryMode::Recursive
                } else {
                    DirectoryMode::Singular
                };

                let sub_matches_encrypt = sub_matches.subcommand_matches("encrypt").unwrap();

                let (keyfile, params) = param_handler(sub_matches_encrypt)?;

                directory::encrypt_directory(
                    sub_matches_encrypt
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    sub_matches_encrypt
                        .value_of("output")
                        .context("No output file/invalid text provided")?,
                    Vec::new(),
                    keyfile,
                    mode,
                    sub_matches_encrypt.is_present("memory"),
                    params,
                )?;
            }
            Some("decrypt") => {}
            None | _ => (),
        },
        _ => (),
    }
    Ok(())
}
