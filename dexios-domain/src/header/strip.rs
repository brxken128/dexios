//! This provides functionality for stripping a header that adheres to the Dexios format.

use super::Error;
use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use core::header::Header;

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub handle: &'a RefCell<RW>,
}

pub fn execute<RW>(req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let (header, _) =
        Header::deserialize(&mut *req.handle.borrow_mut()).map_err(|_| Error::InvalidFile)?;

    req.handle
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::Rewind)?;

    let zeroes = vec![
        0u8;
        header
            .get_size()
            .try_into()
            .map_err(|_| Error::HeaderSizeParse)?
    ];

    req.handle
        .borrow_mut()
        .write_all(&zeroes)
        .map_err(|_| Error::Write)?;

    Ok(())
}
