//! This module handles key-related functionality within `dexios-core`
//!
//! It contains methods for `argon2id` and `balloon` hashing, and securely generating a salt
//!
//! # Examples
//!
//! ```rust,ignore
//! let salt = gen_salt();
//! let secret_data = "secure key".as_bytes().to_vec();
//! let raw_key = Protected::new(secret_data);
//! let key = argon2id_hash(raw_key, &salt, &HeaderVersion::V3).unwrap();
//! ```
use anyhow::Result;

use crate::cipher::Ciphers;
use crate::header::{Header, HeaderVersion};
use crate::primitives::{MASTER_KEY_LEN, SALT_LEN};
use crate::protected::Protected;

/// This handles `argon2id` hashing of a raw key
///
/// It requires a user to generate the salt
///
/// `HeaderVersion` is required as the parameters are linked to specific header versions
///
/// It returns a `Protected<[u8; 32]>` - `Protected` wrappers are used for all sensitive information within `dexios-core`
///
/// This function ensures that `raw_key` is securely erased from memory once hashed
///
/// # Examples
///
/// ```rust,ignore
/// let salt = gen_salt();
/// let secret_data = "secure key".as_bytes().to_vec();
/// let raw_key = Protected::new(secret_data);
/// let key = argon2id_hash(raw_key, &salt, &HeaderVersion::V3).unwrap();
/// ```
///
pub fn argon2id_hash(
    raw_key: Protected<Vec<u8>>,
    salt: &[u8; SALT_LEN],
    version: &HeaderVersion,
) -> Result<Protected<[u8; 32]>> {
    use argon2::Argon2;
    use argon2::Params;

    let params = match version {
        HeaderVersion::V1 => {
            // 8MiB of memory, 8 iterations, 4 levels of parallelism
            Params::new(8192, 8, 4, Some(Params::DEFAULT_OUTPUT_LEN))
                .map_err(|_| anyhow::anyhow!("Error initialising argon2id parameters"))?
        }
        HeaderVersion::V2 => {
            // 256MiB of memory, 8 iterations, 4 levels of parallelism
            Params::new(262_144, 8, 4, Some(Params::DEFAULT_OUTPUT_LEN))
                .map_err(|_| anyhow::anyhow!("Error initialising argon2id parameters"))?
        }
        HeaderVersion::V3 => {
            // 256MiB of memory, 10 iterations, 4 levels of parallelism
            Params::new(262_144, 10, 4, Some(Params::DEFAULT_OUTPUT_LEN))
                .map_err(|_| anyhow::anyhow!("Error initialising argon2id parameters"))?
        }
        HeaderVersion::V4 | HeaderVersion::V5 => {
            return Err(anyhow::anyhow!(
                "argon2id is not supported on header versions above V3."
            ))
        }
    };

    let mut key = [0u8; 32];
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let result = argon2.hash_password_into(raw_key.expose(), salt, &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(anyhow::anyhow!("Error while hashing your key"));
    }

    Ok(Protected::new(key))
}

/// This handles BLAKE3-Balloon hashing of a raw key
///
/// It requires a user to generate the salt
///
/// `HeaderVersion` is required as the parameters are linked to specific header versions
///
/// It's only supported on header versions V4 and above.
///
/// It returns a `Protected<[u8; 32]>` - `Protected` wrappers are used for all sensitive information within `dexios-core`
///
/// This function ensures that `raw_key` is securely erased from memory once hashed
///
/// # Examples
///
/// ```rust,ignore
/// let salt = gen_salt();
/// let secret_data = "secure key".as_bytes().to_vec();
/// let raw_key = Protected::new(secret_data);
/// let key = balloon_hash(raw_key, &salt, &HeaderVersion::V4).unwrap();
/// ```
///
pub fn balloon_hash(
    raw_key: Protected<Vec<u8>>,
    salt: &[u8; SALT_LEN],
    version: &HeaderVersion,
) -> Result<Protected<[u8; 32]>> {
    use balloon_hash::Balloon;

    let params = match version {
        HeaderVersion::V1 | HeaderVersion::V2 | HeaderVersion::V3 => {
            return Err(anyhow::anyhow!(
                "Balloon hashing is not supported in header versions below V4."
            ));
        }
        HeaderVersion::V4 => balloon_hash::Params::new(262_144, 1, 1)
            .map_err(|_| anyhow::anyhow!("Error initialising balloon hashing parameters"))?,
        HeaderVersion::V5 => balloon_hash::Params::new(278_528, 1, 1)
            .map_err(|_| anyhow::anyhow!("Error initialising balloon hashing parameters"))?,
    };

    let mut key = [0u8; 32];
    let balloon = Balloon::<blake3::Hasher>::new(balloon_hash::Algorithm::Balloon, params, None);
    let result = balloon.hash_into(raw_key.expose(), salt, &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(anyhow::anyhow!("Error while hashing your key"));
    }

    Ok(Protected::new(key))
}

#[allow(clippy::module_name_repetitions)]
pub fn decrypt_master_key(
    raw_key: Protected<Vec<u8>>,
    header: &Header,
    // TODO: use custom error instead of anyhow
) -> Result<Protected<[u8; MASTER_KEY_LEN]>> {
    match header.header_type.version {
        HeaderVersion::V1 | HeaderVersion::V2 | HeaderVersion::V3 => {
            argon2id_hash(raw_key, &header.salt.unwrap(), &header.header_type.version)
        }
        HeaderVersion::V4 => {
            let keyslots = header.keyslots.as_ref().unwrap();
            let keyslot = keyslots.first().ok_or_else(|| anyhow::anyhow!("Unable to find a match with the key you provided (maybe you supplied the wrong key?)"))?;
            let key = keyslot.hash_algorithm.hash(raw_key, &keyslot.salt)?;

            let cipher = Ciphers::initialize(key, &header.header_type.algorithm)?;
            cipher
                .decrypt(&keyslot.nonce, keyslot.encrypted_key.as_slice())
                .map(|master_key| vec_to_arr(&master_key))
                .map(Protected::new)
                .map_err(|_| anyhow::anyhow!("Cannot decrypt master key"))
        }
        HeaderVersion::V5 => {
            header
                .keyslots
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Invalid header format"))?
                .iter()
                .find_map(|keyslot| {
                    let key = keyslot.hash_algorithm.hash(raw_key.clone(), &keyslot.salt).ok()?;

                    let cipher = Ciphers::initialize(key, &header.header_type.algorithm).ok()?;
                    cipher
                        .decrypt(&keyslot.nonce, keyslot.encrypted_key.as_slice())
                        .map(|master_key| vec_to_arr(&master_key))
                        .map(Protected::new)
                        .ok()
                })
                .ok_or_else(|| anyhow::anyhow!("Unable to find a match with the key you provided (maybe you supplied the wrong key?)"))
        }
    }
}

// TODO: choose better place for this util
#[must_use]
pub fn vec_to_arr<const N: usize>(master_key_vec: &[u8]) -> [u8; N] {
    let mut master_key = [0u8; N];
    let len = N.min(master_key_vec.len());
    master_key[..len].copy_from_slice(&master_key_vec[..len]);
    master_key
}
