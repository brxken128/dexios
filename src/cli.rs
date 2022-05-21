use clap::{Arg, Command};

// this defines all of the clap subcommands and arguments
// it's long, and clunky, but i feel that's just the nature of the clap builder api
// it returns the ArgMatches so that a match statement can send everything to the correct place
#[allow(clippy::too_many_lines)]
pub fn get_matches() -> clap::ArgMatches {
    Command::new("dexios")
        .version(clap::crate_version!())
        .author("brxken128 <brxken128@tutanota.com>")
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
                        .help("use a keyfile instead of a password"),
                )
                .arg(
                    Arg::new("erase")
                        .long("erase")
                        .value_name("# of passes")
                        .takes_value(true)
                        .require_equals(true)
                        .help("securely erase the input file once complete (default is 16 passes)")
                        .min_values(0)
                        .default_missing_value("16"),
                )
                .arg(
                    Arg::new("hash")
                        .short('H')
                        .long("hash")
                        .takes_value(false)
                        .help("return a blake3 hash of the encrypted file"),
                )
                .arg(
                    Arg::new("skip")
                        .short('y')
                        .long("skip")
                        .takes_value(false)
                        .help("skip all prompts"),
                )
                .arg(
                    Arg::new("bench")
                        .short('b')
                        .long("benchmark")
                        .takes_value(false)
                        .help("don't write the output file to the disk, to prevent wear on flash storage when benchmarking"),
                )
                .arg(
                    Arg::new("stream")
                        .short('s')
                        .long("stream")
                        .takes_value(false)
                        .help("use stream encryption - default")
                        .conflicts_with("memory"),
                )
                .arg(
                    Arg::new("memory")
                        .short('m')
                        .long("memory")
                        .takes_value(false)
                        .help("load the file into memory before encrypting"),
                )
                .arg(
                    Arg::new("password")
                        .short('p')
                        .long("password")
                        .takes_value(false)
                        .help("interactively ask for your password")
                        .conflicts_with("keyfile"),
                )
                .arg(
                    Arg::new("gcm")
                        .short('g')
                        .long("gcm")
                        .takes_value(false)
                        .help("use aes-256-gcm"),
                )
                .arg(
                    Arg::new("xchacha")
                        .short('x')
                        .long("xchacha")
                        .takes_value(false)
                        .help("use xchacha20-poly1305")
                        .conflicts_with("gcm"),
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
                        .help("use a keyfile instead of a password"),
                )
                .arg(
                    Arg::new("erase")
                        .long("erase")
                        .value_name("# of passes")
                        .takes_value(true)
                        .require_equals(true)
                        .help("securely erase the input file once complete (default is 16 passes)")
                        .min_values(0)
                        .default_missing_value("16"),
                )
                .arg(
                    Arg::new("hash")
                        .short('H')
                        .long("hash")
                        .takes_value(false)
                        .help("return a blake3 hash of the encrypted file"),
                )
                .arg(
                    Arg::new("skip")
                        .short('y')
                        .long("skip")
                        .takes_value(false)
                        .help("skip all prompts"),
                )
                .arg(
                    Arg::new("bench")
                        .short('b')
                        .long("benchmark")
                        .takes_value(false)
                        .help("don't write the output file to the disk, to prevent wear on flash storage when benchmarking"),
                )
                .arg(
                    Arg::new("stream")
                        .short('s')
                        .long("stream")
                        .takes_value(false)
                        .help("use stream decryption - default")
                        .conflicts_with("memory"),
                )
                .arg(
                    Arg::new("memory")
                        .short('m')
                        .long("memory")
                        .takes_value(false)
                        .help("load the file into memory before encrypting"),
                )
                .arg(
                    Arg::new("password")
                        .short('p')
                        .long("password")
                        .takes_value(false)
                        .help("interactively ask for your password")
                        .conflicts_with("keyfile"),
                )
                .arg(
                    Arg::new("gcm")
                        .short('g')
                        .long("gcm")
                        .takes_value(false)
                        .help("use aes-256-gcm"),
                )
                .arg(
                    Arg::new("xchacha")
                        .short('x')
                        .long("xchacha")
                        .takes_value(false)
                        .help("use xchacha20-poly1305")
                        .conflicts_with("gcm"),
                ),
        )
        .subcommand(
            Command::new("erase")
                .about("erase a file completely")
                .arg(
                    Arg::new("input")
                        .value_name("input")
                        .takes_value(true)
                        .required(true)
                        .help("the file to erase"),
                )
                .arg(
                    Arg::new("passes")
                        .long("passes")
                        .value_name("# of passes")
                        .takes_value(true)
                        .require_equals(true)
                        .help("specify the number of passes (default is 16)")
                        .min_values(0)
                        .default_missing_value("16"),
                ),
        )
        .get_matches()
}
