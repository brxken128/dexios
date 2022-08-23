use std::io::Seek;

use super::Error;
use dcore::header::HashingAlgorithm;
use dcore::header::Keyslot;
use dcore::header::{Header, HeaderVersion};
use dcore::primitives::gen_nonce;
use dcore::primitives::gen_salt;
use dcore::primitives::Mode;
use dcore::protected::Protected;
use std::cell::RefCell;
use std::io::{Read, Write};

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub handle: &'a RefCell<RW>, // header read+write+seek
    pub raw_key_old: Protected<Vec<u8>>,
    pub raw_key_new: Protected<Vec<u8>>,
    pub hash_algorithm: HashingAlgorithm,
}

pub fn execute<RW>(req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let (header, _) = dcore::header::Header::deserialize(&mut *req.handle.borrow_mut())
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
    let (master_key, _) = super::decrypt_master_key_with_index(
        &keyslots,
        req.raw_key_old,
        &header.header_type.algorithm,
    )?;

    if keyslots.len() == 4 {
        return Err(Error::TooManyKeyslots);
    }

    let salt = gen_salt();
    let master_key_nonce = gen_nonce(&header.header_type.algorithm, &Mode::MemoryMode);

    let key_new = req
        .hash_algorithm
        .hash(req.raw_key_new, &salt)
        .map_err(|_| Error::KeyHash)?;

    let encrypted_master_key = super::encrypt_master_key(
        master_key,
        key_new,
        &master_key_nonce,
        &header.header_type.algorithm,
    )?;

    let keyslot = Keyslot {
        encrypted_key: encrypted_master_key,
        nonce: master_key_nonce,
        salt,
        hash_algorithm: req.hash_algorithm,
    };

    keyslots.push(keyslot);

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
