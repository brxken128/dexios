use anyhow::{Context, Ok, Result};
use clap::{Arg, Command};

mod decrypt;
mod encrypt;
mod erase;
mod prompt;
mod structs;

fn main() -> Result<()> {
    let matches = Command::new("dexios") // add verbose arg?
        .version("5.0.2")
        .author("brxken128 <github.com/brxken128>")
        .about("Secure command-line encryption of files.")
        .subcommand_required(true)
        .subcommand(
            Command::new("encrypt")
                .short_flag('e')
                .about("encrypt a file")
                .arg(
                    Arg::new("input")
                        .value_name("input")
                        .takes_value(true)
                        .required(true)
                        .help("the input file"),
                )
                .arg(
                    Arg::new("output")
                        .value_name("output")
                        .takes_value(true)
                        .required(true)
                        .help("the output file"),
                )
                .arg(
                    Arg::new("keyfile")
                        .short('k')
                        .long("keyfile")
                        .value_name("file")
                        .takes_value(true)
                        .help("use a keyfile for encryption"),
                )
                .arg(
                    Arg::new("erase")
                        .long("erase")
                        .takes_value(false)
                        .help("securely erase the input file once complete"),
                )
                .arg(
                    Arg::new("sha")
                        .short('s')
                        .long("sha512sum")
                        .takes_value(false)
                        .help("return a sha3-512 hash of the encrypted file"),
                )
                .arg(
                    Arg::new("skip")
                        .short('y')
                        .long("skip")
                        .takes_value(false)
                        .help("skip all prompts"),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .short_flag('d')
                .about("decrypt a previously encrypted file")
                .arg(
                    Arg::new("input")
                        .value_name("input")
                        .takes_value(true)
                        .required(true)
                        .help("the input file"),
                )
                .arg(
                    Arg::new("output")
                        .value_name("output")
                        .takes_value(true)
                        .required(true)
                        .help("the output file"),
                )
                .arg(
                    Arg::new("keyfile")
                        .short('k')
                        .long("keyfile")
                        .value_name("file")
                        .takes_value(true)
                        .help("use a keyfile for encryption"),
                )
                .arg(
                    Arg::new("erase")
                        .long("erase")
                        .takes_value(false)
                        .help("securely erase the input file once complete"),
                )
                .arg(
                    Arg::new("sha")
                        .short('s')
                        .long("sha512sum")
                        .takes_value(false)
                        .help("return a sha3-512 hash of the encrypted file"),
                )
                .arg(
                    Arg::new("skip")
                        .short('y')
                        .long("skip")
                        .takes_value(false)
                        .help("skip all prompts"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let mut keyfile = "";
            if sub_matches.is_present("keyfile") {
                keyfile = sub_matches
                    .value_of("keyfile")
                    .context("No keyfile/invalid text provided")?;
            }

            let result = encrypt::encrypt_file(
                sub_matches
                    .value_of("input")
                    .context("No input file/invalid text provided")?,
                sub_matches
                    .value_of("output")
                    .context("No output file/invalid text provided")?,
                keyfile,
                sub_matches.is_present("sha"),
                sub_matches.is_present("skip"),
            );
            if result.is_ok() && sub_matches.is_present("erase") {
                erase::secure_erase(
                    sub_matches
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                )?;
            }
        }
        Some(("decrypt", sub_matches)) => {
            let mut keyfile = "";
            if sub_matches.is_present("keyfile") {
                keyfile = sub_matches
                    .value_of("keyfile")
                    .context("No keyfile/invalid text provided")?;
            }

            let result = decrypt::decrypt_file(
                sub_matches
                    .value_of("input")
                    .context("No input file/invalid text provided")?,
                sub_matches
                    .value_of("output")
                    .context("No output file/invalid text provided")?,
                keyfile,
                sub_matches.is_present("sha"),
                sub_matches.is_present("skip"),
            );
            if result.is_ok() && sub_matches.is_present("erase") {
                erase::secure_erase(
                    sub_matches
                        .value_of("input")
                        .context("No input file/invalid text provided")?,
                )?;
            }
        }
        _ => (),
    }
    Ok(())
}
