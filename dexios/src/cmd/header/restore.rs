use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
};

use crate::cli::prompt::overwrite_check;
use crate::global::states::ForceMode;
use anyhow::{Context, Result};
use core::header::HashingAlgorithm;
use core::header::{Header, HeaderVersion};
use domain::storage::Storage;
use domain::utils::hex_encode;

// this function reads the header from the input file
// it then writes the header to the start of the ouput file
// this can be used for restoring a dumped header to a file that had it's header stripped
// this does not work for files encrypted *with* a detached header
// it implements a check to ensure the header is valid before restoring to a file
pub fn restore(input: &str, output: &str) -> Result<()> {
    let stor = std::sync::Arc::new(domain::storage::FileStorage);

    let input_file = stor.read_file(input)?;

    let output_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(output)
            .with_context(|| format!("Unable to open output file: {}", output))?,
    );

    let req = domain::header::restore::Request {
        reader: input_file.try_reader()?,
        writer: &output_file,
    };

    domain::header::restore::execute(req)?;

    Ok(())
}
