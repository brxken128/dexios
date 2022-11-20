use std::{cell::RefCell, fs::OpenOptions, path::PathBuf};

use anyhow::{Context, Result};
use domain::storage::Storage;

#[derive(clap::Args)]
pub struct Args {
    #[clap(help = "The dumped header file")]
    input: PathBuf,

    #[clap(help = "The encrypted file")]
    output: PathBuf,
}

// this function reads the header from the input file
// it then writes the header to the start of the ouput file
// this can be used for restoring a dumped header to a file that had it's header stripped
// this does not work for files encrypted *with* a detached header
// it implements a check to ensure the header is valid before restoring to a file
pub fn restore(args: Args) -> Result<()> {
    let stor = std::sync::Arc::new(domain::storage::FileStorage);

    let input_file = stor.read_file(args.input)?;

    let output_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(args.output)
            .with_context(|| {
                format!(
                    "Unable to open output file: {}",
                    args.output.to_str().unwrap()
                )
            })?,
    );

    let req = domain::header::restore::Request {
        reader: input_file.try_reader()?,
        writer: &output_file,
    };

    domain::header::restore::execute(req)?;

    Ok(())
}
