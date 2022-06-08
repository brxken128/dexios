//! This module handles key-related functionality within `dexios-core`
//! It contains methods for `argon2id` hashing, and securely generating a salt

use super::primitives::SALT_LEN;

use super::header::HeaderVersion;
use super::protected::Protected;
use anyhow::Result;
use argon2::Argon2;
use argon2::Params;
use rand::prelude::StdRng;
use rand::RngCore;
use rand::SeedableRng;

/// This generates a salt, of the specified `SALT_LEN`
/// This salt can be directly passed to `argon2id_hash()`
#[must_use]
pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt: [u8; SALT_LEN] = [0; SALT_LEN];
    StdRng::from_entropy().fill_bytes(&mut salt);
    salt
}

/// This handles `argon2id` hashing of a raw key
/// It requires a user to generate the salt
/// `HeaderVersion` is required as the parameters are linked to specific header versions
/// It returns a `Protected<[u8; 32]>` - `Protected` wrappers are used for all sensitive information within `dexios-core`
/// This function ensures that `raw_key` is securely erased from memory once hashed
pub fn argon2id_hash(
    raw_key: Protected<Vec<u8>>,
    salt: &[u8; SALT_LEN],
    version: &HeaderVersion,
) -> Result<Protected<[u8; 32]>> {
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
    };

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let result = argon2.hash_password_into(raw_key.expose(), salt, &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(anyhow::anyhow!(
            "Error while hashing your key with argon2id"
        ));
    }

    Ok(Protected::new(key))
}
