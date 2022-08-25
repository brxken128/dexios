//! This provides functionality for dumping a header that adheres to the Dexios format.

use super::Error;
use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use core::header::Header;

pub struct Request<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<W>,
}

pub fn execute<R, W>(req: Request<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let (header, _) =
        Header::deserialize(&mut *req.reader.borrow_mut()).map_err(|_| Error::InvalidFile)?;

    header
        .write(&mut *req.writer.borrow_mut())
        .map_err(|_| Error::Write)?;

    Ok(())
}
