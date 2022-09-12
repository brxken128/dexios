use core::key::vec_to_arr;
use core::primitives::Algorithm;
use core::primitives::ENCRYPTED_MASTER_KEY_LEN;
use core::primitives::MASTER_KEY_LEN;
use core::protected::Protected;
use core::Zeroize;
use core::{cipher::Ciphers, header::Keyslot};

pub mod add;
pub mod change;
pub mod delete;
pub mod verify;

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
        match self {
            Error::HeaderSizeParse => f.write_str("Cannot parse header size"),
            Error::Seek => f.write_str("Unable to seek the data's cursor"),
            Error::HeaderWrite => f.write_str("Unable to write the header"),
            Error::HeaderDeserialize => f.write_str("Unable to deserialize the header"),
            Error::CipherInit => f.write_str("Unable to initialize a cipher"),
            Error::KeyHash => f.write_str("Unable to hash your key"),
            Error::TooManyKeyslots => {
                f.write_str("There are already too many populated keyslots within this file")
            }
            Error::MasterKeyEncrypt => f.write_str("Unable to encrypt master key"),
            Error::Unsupported => {
                f.write_str("The provided request is unsupported with this header version")
            }
            Error::IncorrectKey => f.write_str("The provided key is incorrect"),
        }
    }
}

pub fn decrypt_v5_master_key_with_index(
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
            .hash(raw_key_old.clone(), &keyslot.salt)
            .map_err(|_| Error::KeyHash)?;
        let cipher = Ciphers::initialize(key_old, algorithm).map_err(|_| Error::CipherInit)?;

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

    drop(raw_key_old);

    if master_key == [0u8; MASTER_KEY_LEN] {
        return Err(Error::IncorrectKey);
    }

    Ok((Protected::new(master_key), index))
}

impl std::error::Error for Error {}

// TODO(brxken128): make this available in the core
pub fn encrypt_master_key(
    master_key: Protected<[u8; MASTER_KEY_LEN]>,
    key_new: Protected<[u8; 32]>,
    nonce: &[u8],
    algorithm: &Algorithm,
) -> Result<[u8; ENCRYPTED_MASTER_KEY_LEN], Error> {
    let cipher = Ciphers::initialize(key_new, algorithm).map_err(|_| Error::CipherInit)?;

    let master_key_result = cipher.encrypt(nonce, master_key.expose().as_slice());

    drop(master_key);

    let master_key_encrypted = master_key_result.map_err(|_| Error::MasterKeyEncrypt)?;

    Ok(vec_to_arr(master_key_encrypted))
}
