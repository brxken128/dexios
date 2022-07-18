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

use super::primitives::SALT_LEN;

use super::header::HeaderVersion;
use super::protected::Protected;
use anyhow::Result;
use rand::prelude::ThreadRng;
use rand::RngCore;

/// This generates a salt, of the specified `SALT_LEN`
///
/// This salt can be directly passed to `argon2id_hash()` or `balloon_hash()`
///
/// # Examples
///
/// ```rust,ignore
/// let salt = gen_salt();
/// ```
///
#[must_use]
pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    ThreadRng::default().fill_bytes(&mut salt);
    salt
}

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
