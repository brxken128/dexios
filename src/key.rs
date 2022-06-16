//! This module handles key-related functionality within `dexios-core`
//!
//! It contains methods for `argon2id` hashing, and securely generating a salt
//!
//! # Examples
//!
//! ```
//! let salt = gen_salt();
//! let secret_data = "secure key".as_bytes().to_vec();
//! let raw_key = Protected::new(secret_data);
//! let key = argon2id_hash(raw_key, &salt, &HeaderVersion::V3).unwrap();
//! ```

use super::primitives::SALT_LEN;

use super::header::HeaderVersion;
use super::protected::Protected;
use anyhow::Result;
use rand::prelude::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use zeroize::Zeroize;

/// This generates a salt, of the specified `SALT_LEN`
///
/// This salt can be directly passed to `argon2id_hash()`
///
/// # Examples
///
/// ```
/// let salt = gen_salt();
/// ```
///
#[must_use]
pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt: [u8; SALT_LEN] = [0; SALT_LEN];
    StdRng::from_entropy().fill_bytes(&mut salt);
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
/// ```
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

    let mut key = [0u8; 32];

    let params = match version {
        HeaderVersion::V1 => {
            // 8MiB of memory, 8 iterations, 4 levels of parallelism
            let params = Params::new(8192, 8, 4, Some(Params::DEFAULT_OUTPUT_LEN));
            match params {
                std::result::Result::Ok(parameters) => parameters,
                Err(_) => return Err(anyhow::anyhow!("Error initialising argon2id parameters")),
            }
        }
        HeaderVersion::V2 => {
            // 256MiB of memory, 8 iterations, 4 levels of parallelism
            let params = Params::new(262_144, 8, 4, Some(Params::DEFAULT_OUTPUT_LEN));
            match params {
                std::result::Result::Ok(parameters) => parameters,
                Err(_) => return Err(anyhow::anyhow!("Error initialising argon2id parameters")),
            }
        }
        HeaderVersion::V3 => {
            // 256MiB of memory, 10 iterations, 4 levels of parallelism
            let params = Params::new(262_144, 10, 4, Some(Params::DEFAULT_OUTPUT_LEN));
            match params {
                std::result::Result::Ok(parameters) => parameters,
                Err(_) => return Err(anyhow::anyhow!("Error initialising argon2id parameters")),
            }
        }
        HeaderVersion::V4 => {
            return Err(anyhow::anyhow!(
                "argon2id is not supported on header versions above V3."
            ))
        }
    };

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let result = argon2.hash_password_into(raw_key.expose(), salt, &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(anyhow::anyhow!("Error while hashing your key"));
    }

    Ok(Protected::new(key))
}

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
            ))
        }
        HeaderVersion::V4 => {
            // change this to v4
            let params = balloon_hash::Params::new(262_144, 6, 4);
            match params {
                Ok(parameters) => parameters,
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "Error initialising balloon hashing parameters"
                    ))
                }
            }
        }
    };

    let balloon = Balloon::<blake3::Hasher>::new(balloon_hash::Algorithm::Balloon, params, None);
    let result = balloon.hash(raw_key.expose(), salt);
    drop(raw_key);

    match result {
        Ok(mut key_gen_array) => {
            let mut key_bytes = key_gen_array.to_vec();
            let mut key = [0u8; 32];

            for (i, byte) in key_bytes.iter().enumerate() {
                key[i] = *byte;
            }

            key_bytes.zeroize();
            key_gen_array.zeroize();

            Ok(Protected::new(key))
        }
        Err(_) => Err(anyhow::anyhow!("Error while hashing your key"))
    }
}
