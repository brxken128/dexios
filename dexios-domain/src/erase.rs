//! This provides functionality for "shredding" a file.
//!
//! This will not be effective on flash storage, and if you are planning to release a program that uses this function, I'd recommend putting the default number of passes to 1.

use std::io::{Read, Seek, Write};
use std::path::Path;
use std::sync::Arc;

use crate::storage::Storage;

#[derive(Debug)]
pub enum Error {
    OpenFile,
    Overwrite(crate::overwrite::Error),
    RemoveFile,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::OpenFile => f.write_str("Unable to open file"),
            Error::Overwrite(inner) => write!(f, "Unable to overwrite file: {inner}"),
            Error::RemoveFile => f.write_str("Unable to remove file"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<P: AsRef<Path>> {
    pub path: P,
    pub passes: i32,
}

pub fn execute<RW, P>(stor: Arc<impl Storage<RW> + 'static>, req: Request<P>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
    P: AsRef<Path>,
{
    let file = stor.write_file(req.path).map_err(|_| Error::OpenFile)?;
    let buf_capacity = stor.file_len(&file).map_err(|_| Error::OpenFile)?;

    crate::overwrite::execute(crate::overwrite::Request {
        writer: file
            .try_writer()
            .expect("We're confident that we're in writing mode"),
        buf_capacity,
        passes: req.passes,
    })
    .map_err(Error::Overwrite)?;

    stor.remove_file(file).map_err(|_| Error::RemoveFile)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::storage::InMemoryStorage;

    use super::*;

    #[test]
    fn should_erase_file() {
        let stor = Arc::new(InMemoryStorage::default());
        stor.add_hello_txt();

        let req = Request {
            path: "hello.txt",
            passes: 2,
        };
        match execute(stor.clone(), req) {
            Ok(_) => assert_eq!(stor.files().get(&PathBuf::from("hello.txt")), None),
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_not_open_file() {
        let stor = Arc::new(InMemoryStorage::default());

        let req = Request {
            path: "hello.txt",
            passes: 2,
        };
        match execute(stor, req) {
            Err(Error::OpenFile) => {}
            _ => unreachable!(),
        }
    }
}
