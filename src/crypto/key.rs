use std::time::Instant;

use crate::global::secret::Secret;
use crate::global::states::HeaderVersion;
use crate::global::SALT_LEN;
use anyhow::Result;
use argon2::Argon2;
use argon2::Params;
use paris::success;
use rand::prelude::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use std::result::Result::Ok;

// this generates a salt for password hashing
pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt: [u8; SALT_LEN] = [0; SALT_LEN];
    StdRng::from_entropy().fill_bytes(&mut salt);
    salt
}

// this handles argon2 hashing with the provided key
// it returns the key hashed with a specified salt
// it also ensures that raw_key is zeroed out
pub fn argon2_hash(
    raw_key: Secret<Vec<u8>>,
    salt: [u8; SALT_LEN],
    version: &HeaderVersion,
) -> Result<Secret<[u8; 32]>> {
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

    let hash_start_time = Instant::now();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let result = argon2.hash_password_into(raw_key.expose(), &salt, &mut key);
    drop(raw_key);
    let hash_duration = hash_start_time.elapsed();
    success!(
        "Successfully hashed your key [took {:.2}s]",
        hash_duration.as_secs_f32()
    );

    if result.is_err() {
        return Err(anyhow::anyhow!(
            "Error while hashing your key with argon2id"
        ));
    }

    Ok(Secret::new(key))
}
