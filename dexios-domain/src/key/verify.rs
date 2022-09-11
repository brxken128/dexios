//! This provides functionality for verifying that a decryption key is correct (header version >= V5)

use std::io::Seek;

use super::Error;
use core::header::HeaderVersion;
use core::protected::Protected;
use std::cell::RefCell;
use std::io::Read;

pub struct Request<'a, R>
where
    R: Read + Seek,
{
    pub handle: &'a RefCell<R>, // header read+write+seek
    pub raw_key: Protected<Vec<u8>>,
}

pub fn execute<R>(req: Request<'_, R>) -> Result<(), Error>
where
    R: Read + Seek,
{
    let (header, _) = core::header::Header::deserialize(&mut *req.handle.borrow_mut())
        .map_err(|_| Error::HeaderDeserialize)?;

    if header.header_type.version < HeaderVersion::V5 {
        return Err(Error::Unsupported);
    }

    let keyslots = header.keyslots.clone().unwrap();

    // all of these functions need either the master key, or the index
    let (master_key, _) = super::decrypt_v5_master_key_with_index(
        &keyslots,
        req.raw_key,
        &header.header_type.algorithm,
    )?;

    // ensure the master key is gone from memory in the event that the key is correct
    drop(master_key);

    Ok(())
}
