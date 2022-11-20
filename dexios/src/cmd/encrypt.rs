use crate::global::states::{EraseMode, HashMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;
use crate::ui::prompt::overwrite_check;
use anyhow::Result;
use core::header::{HeaderType, HEADER_VERSION};
use core::primitives::{Algorithm, Mode};
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;

use domain::storage::Storage;

#[derive(clap::Args)]
pub struct Args {
    #[clap(
        long,
        help = "Securely erase the input file once complete (default is 1 pass)"
    )]
    #[clap(long = "header", help = "Use a header file that was dumped")]
    header_location: Option<PathBuf>,

    #[clap(short, long, help = "Use a keyfile instead of a password")]
    keyfile: Option<String>,

    #[clap(
        short,
        long = "erase",
        default_value = "1",
        help = "Securely erase the input file once complete (default is 1 pass)"
    )]
    erase_passes: u32,

    #[clap(
        short = 'H',
        long = "hash",
        default_value_t,
        help = "Return a BLAKE3 hash of the encrypted file"
    )]
    calculate_hash: bool,

    #[clap(short, long, default_value_t, help = "Force all actions")]
    force: bool,

    #[clap(
        long = "auto",
        default_value = "7",
        conflicts_with = "keyfile",
        help = "Autogenerate a passphrase (default is 7 words)"
    )]
    generate_password_words: u32,

    #[clap(long, default_value_t, help = "Use argon2id for password hashing")]
    argon: bool,

    #[clap(long, default_value_t, help = "Use AES-256-GCM for encryption")]
    aes: bool,

    #[clap(help = "The file to decrypt")]
    input: PathBuf,

    #[clap(help = "The output file")]
    output: PathBuf,
}

// this function is for encrypting a file in stream mode
// it handles any user-facing interactiveness, opening files
// it creates the stream object and uses the convenience function provided by dexios-core
pub fn execute(args: Args) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    // 1. validate and prepare options
    if args.input == args.output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    if !overwrite_check(args.output, args.force)? {
        exit(0);
    }

    let input_file = stor.read_file(args.input)?;
    let raw_key = params.key.get_secret(&PasswordState::Validate)?;
    let output_file = stor
        .create_file(args.output)
        .or_else(|_| stor.write_file(args.output))?;

    let header_file = match &args.header_location {
        None => None,
        Some(path) => {
            if !overwrite_check(path, args.force)? {
                exit(0);
            }

            Some(stor.create_file(path).or_else(|_| stor.write_file(path))?)
        }
    };

    // 2. encrypt file
    let req = domain::encrypt::Request {
        reader: input_file.try_reader()?,
        writer: output_file.try_writer()?,
        header_writer: header_file.as_ref().and_then(|f| f.try_writer().ok()),
        raw_key,
        header_type: HeaderType {
            version: HEADER_VERSION,
            mode: Mode::StreamMode,
            algorithm,
        },
        hashing_algorithm: args.hashing_algorithm,
    };
    domain::encrypt::execute(req)?;

    // 3. flush result
    if let Some(header_file) = header_file {
        stor.flush_file(&header_file)?;
    }
    stor.flush_file(&output_file)?;

    if args.calculate_hash {
        super::hashing::hash_stream(&[args.output.to_string()])?;
    }

    super::erase::secure_erase(args.input, args.erase_passes, args.force)?;

    Ok(())
}
