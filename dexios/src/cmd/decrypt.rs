use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;

use crate::global::states::{EraseMode, HashMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;
use crate::ui::prompt::overwrite_check;

use anyhow::Result;

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

    #[clap(help = "The file to decrypt")]
    input: PathBuf,

    #[clap(help = "The output file")]
    output: PathBuf,
}

// this function is for decrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if
// the header says so (backwards-compat)
// it also manages using a detached header file if selected
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

    if !overwrite_check(&args.output, args.force)? {
        exit(0);
    }

    let input_file = stor.read_file(args.input)?;
    let header_file = args
        .header_location
        .map(|path| stor.read_file(path))
        .transpose()?;

    let raw_key = params.key.get_secret(&PasswordState::Direct)?;
    let output_file = stor
        .create_file(args.output)
        .or_else(|_| stor.write_file(args.output))?;

    // 2. decrypt file
    domain::decrypt::execute(domain::decrypt::Request {
        header_reader: header_file.as_ref().and_then(|h| h.try_reader().ok()),
        reader: input_file.try_reader()?,
        writer: output_file.try_writer()?,
        raw_key,
        on_decrypted_header: None,
    })?;

    // 3. flush result
    stor.flush_file(&output_file)?;

    if args.calculate_hash {
        super::hashing::hash_stream(&[input.to_string()])?;
    }

    if let EraseMode::EraseFile(passes) = params.erase {
        super::erase::secure_erase(input, passes, params.force)?;
    }

    Ok(())
}
