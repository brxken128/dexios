use std::path::PathBuf;

use crate::ui::prompt::overwrite_check;
use anyhow::{Context, Result};
use core::header::HashingAlgorithm;
use core::header::{Header, HeaderVersion};
use domain::storage::Storage;
use domain::utils::hex_encode;

#[derive(clap::Args)]
pub struct Args {
    #[clap(short, long, default_value_t, help = "Force all actions")]
    force: bool,

    #[clap(help = "The dumped header file")]
    input: PathBuf,

    #[clap(help = "The encrypted file")]
    output: PathBuf,
}

// this function reads the header fromthe input file and writes it to the output file
// it's used for extracting an encrypted file's header for backups and such
// it implements a check to ensure the header is valid
pub fn execute(args: Args) -> Result<()> {
    let stor = std::sync::Arc::new(domain::storage::FileStorage);
    let input_file = stor.read_file(input)?;

    if !overwrite_check(output, force)? {
        std::process::exit(0);
    }

    let output_file = stor
        .create_file(output)
        .or_else(|_| stor.write_file(output))?;

    let req = domain::header::dump::Request {
        reader: input_file.try_reader()?,
        writer: output_file.try_writer()?,
    };

    domain::header::dump::execute(req)?;

    stor.flush_file(&output_file)?;

    Ok(())
}
