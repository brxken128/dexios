//! This provides functionality for restoring a dumped header that adheres to the Dexios format, provided the target file contains enough empty bytes at the start to do so.

use super::Error;
use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use core::header::Header;

pub struct Request<'a, R, RW>
where
    R: Read + Seek,
    RW: Read + Write + Seek,
{
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<RW>,
}

pub fn execute<R, RW>(req: Request<'_, R, RW>) -> Result<(), Error>
where
    R: Read + Seek,
    RW: Read + Write + Seek,
{
    let (header, _) =
        Header::deserialize(&mut *req.reader.borrow_mut()).map_err(|_| Error::InvalidFile)?;

    let mut header_bytes = vec![
        0u8;
        header
            .get_size()
            .try_into()
            .map_err(|_| Error::HeaderSizeParse)?
    ];
    req.writer
        .borrow_mut()
        .read(&mut header_bytes)
        .map_err(|_| Error::Read)?;

    if !header_bytes.into_iter().all(|b| b == 0) {
        return Err(Error::UnsupportedRestore);
    }

    req.writer
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::Rewind)?;

    header
        .write(&mut *req.writer.borrow_mut())
        .map_err(|_| Error::Write)?;

    Ok(())
}
