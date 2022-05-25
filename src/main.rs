use anyhow::{Context, Result};
use global::parameters::{parameter_handler, Algorithm};
use global::parameters::{DirectoryMode, HiddenFilesMode, PackMode, PrintMode, SkipMode};
use global::BLOCK_SIZE;
use std::result::Result::Ok;

mod cli;
mod decrypt;
mod encrypt;
mod erase;
mod file;
mod global;
mod hashing;
mod header;
mod key;
mod pack;
mod prompt;

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let matches = cli::get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let (keyfile, params) = parameter_handler(sub_matches)?;
            let algorithm = if sub_matches.is_present("gcm") {
                Algorithm::AesGcm
            } else {
                Algorithm::XChaCha20Poly1305
            };

            let result = // stream mode is the default - it'll redirect to memory mode if the file is too small
                encrypt::stream_mode(
                    sub_matches
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    sub_matches
                        .value_of("output")
                        .context("No output file/invalid text provided")?,
                    keyfile,
                    &params,
                    &algorithm,
                );

            return result;
        }
        Some(("decrypt", sub_matches)) => {
            let (keyfile, params) = parameter_handler(sub_matches)?;

            // stream decrypt is the default as it will redirect to memory mode if the header says so
            let result = decrypt::stream_mode(
                sub_matches
                    .value_of("input")
                    .context("No input file/invalid text provided")?,
                sub_matches
                    .value_of("output")
                    .context("No output file/invalid text provided")?,
                keyfile,
                &params,
            );

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

            if file_size.len()
                <= BLOCK_SIZE
                    .try_into()
                    .context("Unable to parse stream block size as u64")?
            {
                hashing::hash_memory(file_name)?;
            } else {
                hashing::hash_stream(file_name)?;
            }
        }
        Some(("pack", sub_matches)) => {
            match sub_matches.subcommand_name() {
                Some("encrypt") => {
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
                        list.iter().map(|x| x.to_string()).collect() // this fixes 'static lifetime issues
                    } else {
                        Vec::new()
                    };

                    let print_mode = if sub_matches.is_present("verbose") {
                        PrintMode::Verbose
                    } else {
                        PrintMode::Quiet
                    };

                    let sub_matches_encrypt = sub_matches.subcommand_matches("encrypt").unwrap();

                    let (keyfile, params) = parameter_handler(sub_matches_encrypt)?;
                    let pack_params = PackMode {
                        compression_level,
                        dir_mode,
                        exclude: excluded,
                        hidden,
                        print_mode,
                    };

                    let algorithm = if sub_matches.is_present("gcm") {
                        Algorithm::AesGcm
                    } else {
                        Algorithm::XChaCha20Poly1305
                    };

                    pack::encrypt_directory(
                        sub_matches_encrypt
                            .value_of("input")
                            .context("No input file/invalid text provided")?,
                        sub_matches_encrypt
                            .value_of("output")
                            .context("No output file/invalid text provided")?,
                        keyfile,
                        pack_params,
                        &params,
                        &algorithm,
                    )?;
                }
                Some("decrypt") => {
                    let print_mode = if sub_matches.is_present("verbose") {
                        PrintMode::Verbose
                    } else {
                        PrintMode::Quiet
                    };

                    let sub_matches_decrypt = sub_matches.subcommand_matches("decrypt").unwrap();

                    let (keyfile, params) = parameter_handler(sub_matches_decrypt)?;

                    pack::decrypt_directory(
                        sub_matches_decrypt
                            .value_of("input")
                            .context("No input file/invalid text provided")?,
                        sub_matches_decrypt
                            .value_of("output")
                            .context("No output file/invalid text provided")?,
                        keyfile,
                        &print_mode,
                        &params,
                    )?;
                }
                _ => (),
            }
        }
        Some(("header", sub_matches)) => match sub_matches.subcommand_name() {
            Some("dump") => {
                let sub_matches_dump = sub_matches.subcommand_matches("dump").unwrap();
                let skip = if sub_matches_dump.is_present("skip") {
                    SkipMode::HidePrompts
                } else {
                    SkipMode::ShowPrompts
                };

                header::dump(
                    sub_matches_dump
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    sub_matches_dump
                        .value_of("output")
                        .context("No output file/invalid text provided")?,
                    skip,
                )?;
            }
            Some("restore") => {
                let sub_matches_restore = sub_matches.subcommand_matches("restore").unwrap();
                let skip = if sub_matches_restore.is_present("skip") {
                    SkipMode::HidePrompts
                } else {
                    SkipMode::ShowPrompts
                };

                header::restore(
                    sub_matches_restore
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    sub_matches_restore
                        .value_of("output")
                        .context("No input file/invalid text provided")?,
                    skip,
                )?;
            }
            Some("strip") => {
                let sub_matches_strip = sub_matches.subcommand_matches("strip").unwrap();
                let skip = if sub_matches_strip.is_present("skip") {
                    SkipMode::HidePrompts
                } else {
                    SkipMode::ShowPrompts
                };

                header::strip(
                    sub_matches_strip
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                    skip,
                )?;
            }
            _ => (),
        },
        _ => (),
    }
    Ok(())
}
