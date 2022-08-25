//! This provides functionality for adding a key to a header that both adheres to the Dexios format, and is using a version >= V5.

use super::Error;
use core::header::{Header, HeaderVersion};
use core::protected::Protected;
use std::cell::RefCell;
use std::io::Seek;
use std::io::{Read, Write};

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub handle: &'a RefCell<RW>, // header read+write+seek
    pub raw_key_old: Protected<Vec<u8>>,
}

pub fn execute<RW>(req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let (header, _) = core::header::Header::deserialize(&mut *req.handle.borrow_mut())
        .map_err(|_| Error::HeaderDeserialize)?;

    if header.header_type.version < HeaderVersion::V5 {
        return Err(Error::Unsupported);
    }

    let header_size: i64 = header
        .get_size()
        .try_into()
        .map_err(|_| Error::HeaderSizeParse)?;

    req.handle
        .borrow_mut()
        .seek(std::io::SeekFrom::Current(-header_size))
        .map_err(|_| Error::Seek)?;

    // this gets modified, then any changes from below are written at the end
    let mut keyslots = header.keyslots.clone().unwrap();

    // all of these functions need either the master key, or the index
    let (_, index) = super::decrypt_master_key_with_index(
        &keyslots,
        req.raw_key_old,
        &header.header_type.algorithm,
    )?;

    keyslots.remove(index);

    // recreate header and inherit everything (except keyslots)
    let header_new = Header {
        nonce: header.nonce,
        salt: header.salt,
        keyslots: Some(keyslots),
        header_type: header.header_type,
    };

    // write the header to the handle
    header_new
        .write(&mut *req.handle.borrow_mut())
        .map_err(|_| Error::HeaderWrite)?;

    Ok(())
}
