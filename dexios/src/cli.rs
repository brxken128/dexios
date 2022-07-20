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
                .help("Securely erase the input file once complete (default is 2 passes)")
                .min_values(0)
                .default_missing_value("2"),
        )
        .arg(
            Arg::new("hash")
                .short('H')
                .long("hash")
                .takes_value(false)
                .help("Return a BLAKE3 hash of the encrypted file"),
        )
        .arg(
            Arg::new("autogenerate")
                .long("auto")
                .takes_value(false)
                .help("Autogenerate a passphrase")
                .conflicts_with("keyfile"),
        )
        .arg(
            Arg::new("header")
                .long("header")
                .value_name("file")
                .takes_value(true)
                .help("Store the header separately from the file"),
        )
        .arg(
            Arg::new("skip")
                .short('y')
                .long("skip")
                .takes_value(false)
                .help("Skip all prompts"),
        )
        .arg(
            Arg::new("aead")
                .short('a')
                .long("aead")
                .value_name("aead to use for encryption")
                .takes_value(true)
                .help("select an AEAD (\"dexios list aead\" to see all possible values)"),
        );

    let decrypt = Command::new("decrypt")
        .short_flag('d')
        .about("Decrypt a file")
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
                .help("Securely erase the input file once complete (default is 2 passes)")
                .min_values(0)
                .default_missing_value("2"),
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
        );

    Command::new("dexios")
        .version(clap::crate_version!())
        .author("brxken128 <brxken128@tutanota.com>")
        .about("Secure, fast and modern command-line encryption of files.")
        .subcommand_required(true)
        .arg_required_else_help(true)
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
                        .help("Specify the number of passes (default is 2)")
                        .min_values(0)
                        .default_missing_value("2"),
                ),
        )
        .subcommand(
            Command::new("hash").about("Hash files with BLAKE3").arg(
                Arg::new("input")
                    .value_name("input")
                    .takes_value(true)
                    .required(true)
                    .help("The file(s) to hash")
                    .min_values(1)
                    .multiple_occurrences(true),
            ),
        )
        .subcommand(
            Command::new("list")
                .short_flag('l')
                .about("List Dexios values")
                .arg(
                    Arg::new("input")
                        .value_name("input")
                        .takes_value(true)
                        .required(true)
                        .help("The item to list"),
                ),
        )
        .subcommand(
            Command::new("pack")
            .about("Pack and encrypt an entire directory")
            .short_flag('p')
            .arg(
                Arg::new("output")
                    .value_name("output")
                    .takes_value(true)
                    .required(true)
                    .help("The output file"),
            )
            .arg(
                Arg::new("input")
                    .value_name("input")
                    .takes_value(true)
                    .multiple_values(true)
                    .required(true)
                    .help("The directory to encrypt"),
            )
            .arg(
                Arg::new("erase")
                    .long("erase")
                    .takes_value(false)
                    .help("Securely erase every file from the source directory, before deleting the directory")
            )
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .takes_value(false)
                    .help("Show a detailed output"),
            )
            .arg(
                Arg::new("autogenerate")
                    .long("auto")
                    .takes_value(false)
                    .help("Autogenerate a passphrase")
                    .conflicts_with("keyfile"),
            )
            .arg(
                Arg::new("header")
                    .long("header")
                    .value_name("file")
                    .takes_value(true)
                    .help("Store the header separately from the file"),
            )
            .arg(
                Arg::new("zstd")
                    .short('z')
                    .long("zstd")
                    .takes_value(false)
                    .help("Use ZSTD compression"),
            )
            .arg(
                Arg::new("recursive")
                    .short('r')
                    .long("recursive")
                    .takes_value(false)
                    .help("Index files and folders within other folders (index recursively)"),
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
                Arg::new("aead")
                    .short('a')
                    .long("aead")
                    .value_name("aead to use for encryption")
                    .takes_value(true)
                    .help("select an AEAD (\"dexios list aead\" to see all possible values)"),
            )
        )
        .subcommand(
            Command::new("unpack")
                .short_flag('u')
                .about("Unpack a previously-packed file")
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
                        .help("Securely erase the input file once complete (default is 2 passes)")
                        .min_values(0)
                        .default_missing_value("2"),
                )
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .long("verbose")
                        .takes_value(false)
                        .help("Show a detailed output"),
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
        )
        .subcommand(
            Command::new("header")
                .about("Manipulate encrypted headers (for advanced users)")
                .subcommand_required(true)
                .subcommand(
                    Command::new("update-key")
                        .about("Update an encrypted file's key (Password only)")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .takes_value(true)
                                .required(true)
                                .help("The encrypted file"),
                        )
                        .arg(
                            Arg::new("autogenerate")
                                .long("auto")
                                .takes_value(false)
                                .help("Autogenerate a passphrase (this will be your new key)")
                                .conflicts_with("keyfile-new"),
                        )
                        .arg(
                            Arg::new("keyfile-old")
                                .short('k')
                                .long("keyfile-old")
                                .value_name("file")
                                .takes_value(true)
                                .help("Use your old keyfile for decryption"),
                        )
                        .arg(
                            Arg::new("keyfile-new")
                                .short('n')
                                .long("keyfile-new")
                                .value_name("file")
                                .takes_value(true)
                                .help("Use a keyfile as the new key"),
                        ),
                )
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
                        ),
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
                                .help("The dumped header file"),
                        )
                        .arg(
                            Arg::new("output")
                                .value_name("output")
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
                        ),
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
                        ),
                )
                .subcommand(
                    Command::new("details")
                        .about("Show details of a header")
                        .arg_required_else_help(true)
                        .arg(
                            Arg::new("input")
                                .value_name("input")
                                .takes_value(true)
                                .required(true)
                                .help("The encrypted/header file"),
                        ),
                ),
        )
        .get_matches()
}
