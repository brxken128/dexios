use std::{cell::RefCell, fs::OpenOptions, path::PathBuf};

use anyhow::{Context, Result};

#[derive(clap::Args)]
pub struct Args {
    #[clap(help = "The encrypted file")]
    input: PathBuf,
}

// this wipes the length of the header from the provided file
// the header must be intact for this to work, as the length varies between the versions
// it can be useful for storing the header separate from the file, to make an attacker's life that little bit harder
// it implements a check to ensure the header is valid before stripping
pub fn execute(args: Args) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(args.input)
            .with_context(|| {
                format!(
                    "Unable to open input file: {}",
                    args.input.to_str().unwrap()
                )
            })?,
    );

    let req = domain::header::strip::Request {
        handle: &input_file,
    };

    domain::header::strip::execute(req)?;

    Ok(())
}
