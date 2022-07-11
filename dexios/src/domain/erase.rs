use crate::domain;
use std::io::{Read, Seek, Write};
use std::path::Path;

use domain::storage::Storage;

#[derive(Debug)]
pub enum Error {
    OpenFile,
    Overwrite(domain::overwrite::Error),
    RemoveFile,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            OpenFile => f.write_str("Unable to open file"),
            Overwrite(inner) => write!(f, "Unable to overwrite file: {}", inner),
            RemoveFile => f.write_str("Unable to write file"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<P: AsRef<Path>> {
    path: P,
    passes: i32,
}

pub fn execute<RW: Read + Write + Seek, P: AsRef<Path>>(
    stor: &impl Storage<RW>,
    req: Request<P>,
) -> Result<(), Error> {
    // TODO: add logic for directories

    let file = stor.write_file(req.path).map_err(|_| Error::OpenFile)?;
    let buf_capacity = stor.file_len(&file).map_err(|_| Error::OpenFile)?;

    domain::overwrite::execute(domain::overwrite::Request {
        writer: file
            .try_writer()
            .expect("We're confident that we're in writing mode"),
        buf_capacity,
        passes: req.passes,
    })
    .map_err(Error::Overwrite)?;

    stor.remove_file(&file).map_err(|_| Error::RemoveFile)?;

    Ok(())
}
