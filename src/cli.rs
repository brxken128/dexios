use clap::{Arg, Command};

// this defines all of the clap subcommands and arguments
// it's long, and clunky, but i feel that's just the nature of the clap builder api
// it returns the ArgMatches so that a match statement can send everything to the correct place
#[allow(clippy::too_many_lines)]
pub fn get_matches() -> clap::ArgMatches {
    let encrypt = Command::new("encrypt")
        .short_flag('e')
        .about("Encrypt a file")
        .arg(
            Arg::new("input")
                .value_name("input")
                .takes_value(true)
                .required(true)
                .help("The file to encrypt"),
        )
        .arg(
            Arg::new("output")
                .value_name("output")
                .takes_value(true)
                .required(true)
                .help("The output file"),
        )
        .arg(
            Arg::new("keyfile")
                .short('k')
                .long("keyfile")
                .value_name("file")
                .takes_value(true)
                .help("Use a keyfile instead of a password"),
        )
        .arg(
            Arg::new("erase")
                .long("erase")
                .value_name("# of passes")
                .takes_value(true)
                .require_equals(true)
                .help("Securely erase the input file once complete (default is 16 passes)")
                .min_values(0)
                .default_missing_value("16"),
        )
        .arg(
            Arg::new("hash")
                .short('H')
                .long("hash")
                .takes_value(false)
                .help("Return a BLAKE3 hash of the encrypted file"),
        )
        .arg(
            Arg::new("skip")
                .short('y')
                .long("skip")
                .takes_value(false)
                .help("Skip all prompts"),
        )
        .arg(
            Arg::new("bench")
                .short('b')
                .long("benchmark")
                .takes_value(false)
                .help("Don't write the output file to the disk, to prevent wear on flash storage when benchmarking"),
        )
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .takes_value(false)
                .help("Interactively ask for your password")
                .conflicts_with("keyfile"),
        )
        .arg(
            Arg::new("gcm")
                .short('g')
                .long("gcm")
                .takes_value(false)
                .help("Use AES-256-GCM"),
        )
        .arg(
            Arg::new("xchacha")
                .short('x')
                .long("xchacha")
                .takes_value(false)
                .help("Use XChaCha20-Poly1305 (default)")
                .conflicts_with("gcm"),
        );

    let decrypt = Command::new("decrypt")
        .short_flag('d')
        .about("Decrypt a previously encrypted file")
        .arg(
            Arg::new("input")
                .value_name("input")
                .takes_value(true)
                .required(true)
                .help("The file to decrypt"),
        )
        .arg(
            Arg::new("output")
                .value_name("output")
                .takes_value(true)
                .required(true)
                .help("The output file"),
        )
        .arg(
            Arg::new("keyfile")
                .short('k')
                .long("keyfile")
                .value_name("file")
                .takes_value(true)
                .help("Use a keyfile instead of a password"),
        )
        .arg(
            Arg::new("header")
                .long("header")
                .value_name("file")
                .takes_value(true)
                .help("Use a header file that was dumped"),
        )
        .arg(
            Arg::new("erase")
                .long("erase")
                .value_name("# of passes")
                .takes_value(true)
                .require_equals(true)
                .help("Securely erase the input file once complete (default is 16 passes)")
                .min_values(0)
                .default_missing_value("16"),
        )
        .arg(
            Arg::new("hash")
                .short('H')
                .long("hash")
                .takes_value(false)
                .help("Return a BLAKE3 hash of the encrypted file"),
        )
        .arg(
            Arg::new("skip")
                .short('y')
                .long("skip")
                .takes_value(false)
                .help("Skip all prompts"),
        )
        .arg(
            Arg::new("bench")
                .short('b')
                .long("benchmark")
                .takes_value(false)
                .help("Don't write the output file to the disk, to prevent wear on flash storage when benchmarking"),
        )
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .takes_value(false)
                .help("Interactively ask for your password")
                .conflicts_with("keyfile"),
        );

    Command::new("dexios")
        .version(clap::crate_version!())
        .author("brxken128 <brxken128@tutanota.com>")
        .about("Secure, fast and modern command-line encryption of files.")
        .subcommand_required(true)
        .subcommand(encrypt.clone())
        .subcommand(decrypt.clone())
        .subcommand(
            Command::new("erase")
                .about("Erase a file completely")
                .arg(
                    Arg::new("input")
                        .value_name("input")
                        .takes_value(true)
                        .required(true)
                        .help("The file to erase"),
                )
                .arg(
                    Arg::new("passes")
                        .long("passes")
                        .value_name("# of passes")
                        .takes_value(true)
                        .require_equals(true)
                        .help("Specify the number of passes (default is 16)")
                        .min_values(0)
                        .default_missing_value("16"),
                ),
        )
        .subcommand(
            Command::new("hash")
                .about("Hash a file")
                .arg(
                    Arg::new("input")
                        .value_name("input")
                        .takes_value(true)
                        .required(true)
                        .help("The file to hash"),
                ),
        )
        .subcommand(
            Command::new("pack")
                .about("Pack a directory and then encrypt/decrypt it")
                .subcommand_required(true)
                .arg(
                    Arg::new("recursive")
                        .short('r')
                        .long("recursive")
                        .takes_value(false)
                        .help("Index files/folders recursively (encrypt mode only)"),
                )
                .arg(
                    Arg::new("exclude")
                        .long("exclude")
                        .value_name("pattern to exclude")
                        .takes_value(true)
                        .require_equals(true)
                        .help("Exclude a file/folder (e.g. --exclude=\"Documents\") (encrypt mode only)")
                        .min_values(0)
                        .multiple_occurrences(true),
                )
                .arg(
                    Arg::new("level")
                        .long("level")
                        .value_name("level of compression (0-9)")
                        .takes_value(true)
                        .require_equals(true)
                        .help("Specify the deflate compression level (default is 6)")
                        .min_values(0)
                        .default_missing_value("6"),
                )
                .arg(
                    Arg::new("hidden")
                        .long("include-hidden")
                        .takes_value(false)
                        .help("Include hidden files and folders"),
                )
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .long("verbose")
                        .takes_value(false)
                        .help("Provide more output on what's happening"),
                )
                .subcommand(encrypt.clone())
                .subcommand(decrypt.clone()),
        )
        .subcommand(
            Command::new("header")
                .about("Dexios header functions (advanced users only!)")
                .subcommand_required(true)
                .subcommand(
                    Command::new("dump")
                        .about("Dump a header")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .takes_value(true)
                                .required(true)
                                .help("The encrypted file"),
                        )
                        .arg(
                            Arg::new("output")
                                .value_name("output")
                                .takes_value(true)
                                .required(true)
                                .help("The output file"),
                        )
                        .arg(
                            Arg::new("skip")
                                .short('y')
                                .long("skip")
                                .takes_value(false)
                                .help("Skip all prompts"),
                        )
                )
                .subcommand(
                    Command::new("restore")
                        .about("Restore a header")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .takes_value(true)
                                .required(true)
                                .help("The header file"),
                        )
                        .arg(
                            Arg::new("output")
                                .value_name("output")
                                .takes_value(true)
                                .required(true)
                                .help("The encrypted file to restore the header to"),
                        )
                        .arg(
                            Arg::new("skip")
                                .short('y')
                                .long("skip")
                                .takes_value(false)
                                .help("Skip all prompts"),
                        )
                )
                .subcommand(
                    Command::new("strip")
                        .about("Strip a header")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .takes_value(true)
                                .required(true)
                                .help("The encrypted file"),
                        )
                        .arg(
                            Arg::new("skip")
                                .short('y')
                                .long("skip")
                                .takes_value(false)
                                .help("Skip all prompts"),
                        )
                )
        )
        .get_matches()
}
