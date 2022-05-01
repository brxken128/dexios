use std::process::exit;

use clap::{Arg, Command};
use colored::Colorize;
use anyhow::{Result, Ok, Context};

mod encrypt;
mod decrypt;
mod structs;
mod erase;

fn main() -> Result<()> {
    let matches = Command::new("dexios") // add verbose arg?
    .version("1.3.0")
    .author("brxken128 <github.com/brxken128>")
    .about("Secure command-line encryption of files.")
    .arg_required_else_help(true)
    .arg(Arg::new("encrypt")
            .short('e')
            .long("encrypt")
            .takes_value(false)
            .help("encrypt a file"))
    .arg(Arg::new("decrypt")
            .short('d')
            .long("decrypt")
            .takes_value(false)
            .help("decrypt a previously encrypted file"))
    .arg(Arg::new("keyfile")
            .short('k')
            .long("keyfile")
            .value_name("file")
            .takes_value(true)
            .help("use a keyfile for encryption"))
    .arg(Arg::new("password")
            .short('p')
            .long("password")
            .takes_value(false)
            .help("ask for a password (default)"))
    .arg(Arg::new("input")
            .short('i')
            .long("input")
            .value_name("input file")
            .takes_value(true)
            .help("the input file (required)"))
    .arg(Arg::new("output")
            .short('o')
            .long("output")
            .value_name("output file")
            .takes_value(true)
            .help("the output file (required)"))
    .arg(Arg::new("erase")
            .long("erase")
            .takes_value(false)
            .help("securely erase the input file once complete"))
    .get_matches();

    if !matches.is_present("encrypt") && !matches.is_present("decrypt") {
        println!("{}", "No task provided, exiting.".red());
        exit(1);
    }
    if matches.is_present("encrypt") && matches.is_present("decrypt") {
        println!("{}", "Can't encrypt and decrypt, exiting.".red());
        exit(1);
    }
    if matches.value_of("input").is_none() || matches.value_of("output").is_none() {
        println!("{}", "No input/output file specified, exiting.".red());
        exit(1);
    }
    if matches.is_present("encrypt") { // if we are encrypting
        let mut keyfile = "";
        if matches.is_present("keyfile") {
            keyfile = matches.value_of("keyfile").context("No keyfile/invalid text provided")?;
        }

        let result = encrypt::encrypt_file(
            matches.value_of("input").context("No input file/invalid text provided")?,
            matches.value_of("output").context("No output file/invalid text provided")?,
            keyfile,
        );

        if result.is_ok() && matches.is_present("erase") { erase::secure_erase(matches.value_of("input").context("No input file/invalid text provided")?)?; }
    }

    if matches.is_present("decrypt") { // if we are decrypting
        let mut keyfile = "";
        if matches.is_present("keyfile") {
            keyfile = matches.value_of("keyfile").context("No keyfile/invalid text provided")?;
        }

        let result = decrypt::decrypt_file(
            matches.value_of("input").context("No input file/invalid text provided")?,
            matches.value_of("output").context("No output file/invalid text provided")?,
            keyfile,
        );

        if result.is_ok() && matches.is_present("erase") { erase::secure_erase(matches.value_of("input").context("No input file/invalid text provided")?)?; }
    }
    Ok(())
}
