use std::io::Seek;

use dexios_core::header::HashingAlgorithm;
use dexios_core::header::{Header, HeaderVersion};
use dexios_core::key::vec_to_arr;
use dexios_core::primitives::gen_salt;
use dexios_core::primitives::Algorithm;
use dexios_core::primitives::Mode;
use dexios_core::primitives::ENCRYPTED_MASTER_KEY_LEN;
use dexios_core::primitives::MASTER_KEY_LEN;
use dexios_core::protected::Protected;
use dexios_core::Zeroize;
use dexios_core::{cipher::Ciphers, header::Keyslot};
use dexios_core::primitives::gen_nonce;
use std::cell::RefCell;
use std::io::{Read, Write};

#[derive(Debug)]
pub enum Error {
    HeaderSizeParse,
    Unsupported,
    IncorrectKey,
    MasterKeyEncrypt,
    TooManyKeyslots,
    KeyHash,
    CipherInit,
    HeaderDeserialize,
    HeaderWrite,
    Seek,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            HeaderSizeParse => f.write_str("Cannot parse header size"),
            Seek => f.write_str("Unable to seek the data's cursor"),
            HeaderWrite => f.write_str("Unable to write the header"),
            HeaderDeserialize => f.write_str("Unable to deserialize the header"),
            CipherInit => f.write_str("Unable to initialize a cipher"),
            KeyHash => f.write_str("Unable to hash your key"),
            TooManyKeyslots => {
                f.write_str("There are already too many populated keyslots within this file")
            }
            MasterKeyEncrypt => f.write_str("Unable to encrypt master key"),
            Unsupported => {
                f.write_str("The provided request is unsupported with this header version")
            }
            IncorrectKey => {
                f.write_str("Unable to decrypt the master key (maybe you supplied the wrong key?)")
            }
        }
    }
}

pub fn decrypt_master_key_with_index(
    keyslots: &[Keyslot],
    raw_key_old: Protected<Vec<u8>>,
    algorithm: &Algorithm,
) -> Result<(Protected<[u8; MASTER_KEY_LEN]>, usize), Error> {
    let mut index = 0;
    let mut master_key = [0u8; MASTER_KEY_LEN];

    // we need the index, so we can't use `decrypt_master_key()`
    for (i, keyslot) in keyslots.iter().enumerate() {
        let key_old = keyslot
            .hash_algorithm
            .hash(raw_key_old.clone(), &keyslot.salt).map_err(|_| Error::KeyHash)?;
        let cipher = Ciphers::initialize(key_old, &algorithm).map_err(|_| Error::CipherInit)?;

        let master_key_result = cipher.decrypt(&keyslot.nonce, keyslot.encrypted_key.as_slice());

        if master_key_result.is_err() {
            continue;
        }

        let mut master_key_decrypted = master_key_result.unwrap();
        let len = MASTER_KEY_LEN.min(master_key_decrypted.len());
        master_key[..len].copy_from_slice(&master_key_decrypted[..len]);
        master_key_decrypted.zeroize();

        index = i;

        drop(cipher);
        break;
    }

    if master_key == [0u8; MASTER_KEY_LEN] {
        return Err(Error::IncorrectKey);
    }

    Ok((Protected::new(master_key), index))
}

impl std::error::Error for Error {}

#[derive(PartialEq)]
pub enum RequestType {
    Change,
    Delete,
    Add,
}

// TODO(brxken128): make this available in the core
pub fn encrypt_master_key(
    master_key: Protected<[u8; MASTER_KEY_LEN]>,
    key_new: Protected<[u8; 32]>,
    nonce: &[u8],
    algorithm: &Algorithm,
) -> Result<[u8; ENCRYPTED_MASTER_KEY_LEN], Error> {
    let cipher = Ciphers::initialize(key_new, &algorithm).map_err(|_| Error::CipherInit)?;

    let master_key_result = cipher.encrypt(nonce, master_key.expose().as_slice());

    drop(master_key);

    let master_key_encrypted = master_key_result.map_err(|_| Error::MasterKeyEncrypt)?;

    Ok(vec_to_arr(master_key_encrypted))
}

pub struct Request<'a, W>
where
    W: Read + Write + Seek,
{
    pub handle: &'a RefCell<W>, // header read+write+seek
    pub raw_key_old: Protected<Vec<u8>>,
    pub raw_key_new: Option<Protected<Vec<u8>>>, // only required for add+change
    pub request_type: RequestType,
    pub hash_algorithm: Option<HashingAlgorithm>, // only required for add+change
}

pub fn execute<W>(req: Request<W>) -> Result<(), Error>
where
    W: Read + Write + Seek,
{
    let (header, _) = dexios_core::header::Header::deserialize(&mut *req.handle.borrow_mut()).map_err(|_| Error::HeaderDeserialize)?;

    if header.header_type.version < HeaderVersion::V5 {
        return Err(Error::Unsupported);
    }

    let header_size: i64 = header
        .get_size()
        .try_into()
        .map_err(|_| Error::HeaderSizeParse)?;

    req.handle
        .borrow_mut()
        .seek(std::io::SeekFrom::Current(-header_size)).map_err(|_| Error::Seek)?;

    // this gets modified, then any changes from below are written at the end
    let mut keyslots = header.keyslots.clone().unwrap();

    // all of these functions need either the master key, or the index
    let (master_key, index) =
        decrypt_master_key_with_index(&keyslots, req.raw_key_old, &header.header_type.algorithm)?;

    match req.request_type {
        RequestType::Add => {
            let hash_algorithm = req.hash_algorithm.unwrap(); // add error handling

            if keyslots.len() == 4 {
                return Err(Error::TooManyKeyslots);
            }

            let salt = gen_salt();
            let master_key_nonce = gen_nonce(&header.header_type.algorithm, &Mode::MemoryMode);

            let key_new = hash_algorithm.hash(req.raw_key_new.unwrap(), &salt).map_err(|_| Error::KeyHash)?;

            let encrypted_master_key = encrypt_master_key(
                master_key,
                key_new,
                &master_key_nonce,
                &header.header_type.algorithm,
            )?;

            let keyslot = Keyslot {
                encrypted_key: encrypted_master_key,
                nonce: master_key_nonce,
                salt,
                hash_algorithm,
            };

            keyslots.push(keyslot);
        }
        RequestType::Change => {
            let hash_algorithm = req.hash_algorithm.unwrap(); // add error handling

            let salt = gen_salt();
            let key_new = hash_algorithm.hash(req.raw_key_new.unwrap(), &salt).map_err(|_| Error::KeyHash)?;

            let master_key_nonce = gen_nonce(&header.header_type.algorithm, &Mode::MemoryMode);

            let encrypted_master_key = encrypt_master_key(
                master_key,
                key_new,
                &master_key_nonce,
                &header.header_type.algorithm,
            )?;

            keyslots[index] = Keyslot {
                encrypted_key: encrypted_master_key,
                nonce: master_key_nonce,
                salt,
                hash_algorithm,
            };
        }
        RequestType::Delete => {
            keyslots.remove(index);
        }
    }

    // recreate header and inherit everything (except keyslots)
    let header_new = Header {
        nonce: header.nonce,
        salt: header.salt,
        keyslots: Some(keyslots),
        header_type: header.header_type,
    };

    // write the header to the handle
    header_new.write(&mut *req.handle.borrow_mut()).map_err(|_| Error::HeaderWrite)?;

    Ok(())
}