// TODO(brxken128): give this file a better name
use std::{fs::OpenOptions, io::Seek};

use crate::global::states::Key;
use crate::global::states::PasswordState;
use crate::utils::gen_salt;
use anyhow::{Context, Result};
use dexios_core::header::HashingAlgorithm;
use dexios_core::header::{Header, HeaderVersion};
use dexios_core::primitives::Mode;
use dexios_core::primitives::ENCRYPTED_MASTER_KEY_LEN;
use dexios_core::primitives::MASTER_KEY_LEN;
use dexios_core::protected::Protected;
use dexios_core::Zeroize;
use dexios_core::{cipher::Ciphers, header::Keyslot};
use dexios_core::{key::balloon_hash, primitives::gen_nonce};
use paris::info;
use paris::success;
use std::time::Instant;

// this functions take both an old and a new key state
// these key states can be auto generated (new key only), keyfiles or user provided
// it hashes both of them, decrypts the master key with the old key, and re-encrypts it with the new key
// it then writes the updated header to the file
// the AAD remains the same as V4+ AAD does not contain the master key or the nonce
pub fn change_key(input: &str, key_old: &Key, key_new: &Key) -> Result<()> {
    let mut input_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(input)
        .with_context(|| format!("Unable to open input file: {}", input))?;

    let (header, _) = dexios_core::header::Header::deserialize(&mut input_file)?;

    let header_size: i64 = header
        .get_size()
        .try_into()
        .context("Unable to convert header size (u64) to i64")?;

    match header.header_type.version {
        HeaderVersion::V1 | HeaderVersion::V2 | HeaderVersion::V3 => {
            return Err(anyhow::anyhow!(
                "Updating a key is not supported in header versions below V4."
            ));
        }
        HeaderVersion::V4 => {
            let keyslot = header.keyslots.clone().unwrap();

            if keyslots.len() < 1 {
                return Err(anyhow::anyhow!("No keyslots found, so we cannot continue."));
            }

            match key_old {
                Key::User => info!("Please enter your old key below"),
                Key::Keyfile(_) => info!("Reading your old keyfile"),
                _ => (),
            }
            let raw_key_old = key_old.get_secret(&PasswordState::Direct)?;

            match key_new {
                Key::Generate => info!("Generating a new key"),
                Key::User => info!("Please enter your new key below"),
                Key::Keyfile(_) => info!("Reading your new keyfile"),
                Key::Env => (),
            }
            let raw_key_new = key_new.get_secret(&PasswordState::Validate)?;

            let hash_start_time = Instant::now();
            let key_old = balloon_hash(raw_key_old, &keyslot[0].salt, &header.header_type.version)?;
            let hash_duration = hash_start_time.elapsed();
            success!(
                "Successfully hashed your old key [took {:.2}s]",
                hash_duration.as_secs_f32()
            );

            let hash_start_time = Instant::now();
            let key_new = balloon_hash(
                raw_key_new,
                &header.salt.unwrap(),
                &header.header_type.version,
            )?;
            let hash_duration = hash_start_time.elapsed();
            success!(
                "Successfully hashed your new key [took {:.2}s]",
                hash_duration.as_secs_f32()
            );

            let cipher = Ciphers::initialize(key_old, &header.header_type.algorithm)?;

            let master_key_result =
                cipher.decrypt(&keyslot[0].nonce, keyslot[0].encrypted_key.as_slice());
            let mut master_key_decrypted = master_key_result.map_err(|_| {
                anyhow::anyhow!(
                    "Unable to decrypt your master key (maybe you supplied the wrong key?)"
                )
            })?;

            let mut master_key = [0u8; MASTER_KEY_LEN];
            let len = MASTER_KEY_LEN.min(master_key_decrypted.len());
            master_key[..len].copy_from_slice(&master_key_decrypted[..len]);

            master_key_decrypted.zeroize();
            let master_key = Protected::new(master_key);

            drop(cipher);

            let cipher = Ciphers::initialize(key_new, &header.header_type.algorithm)?;

            let master_key_nonce_new = gen_nonce(&header.header_type.algorithm, &Mode::MemoryMode);
            let master_key_result =
                cipher.encrypt(&master_key_nonce_new, master_key.expose().as_slice());

            drop(master_key);

            let master_key_encrypted = master_key_result
                .map_err(|_| anyhow::anyhow!("Unable to encrypt your master key"))?;

            let mut master_key_encrypted_array = [0u8; ENCRYPTED_MASTER_KEY_LEN];

            let len = ENCRYPTED_MASTER_KEY_LEN.min(master_key_encrypted.len());
            master_key_encrypted_array[..len].copy_from_slice(&master_key_encrypted[..len]);

            let keyslots = vec![Keyslot {
                encrypted_key: master_key_encrypted_array,
                hash_algorithm: keyslot[0].hash_algorithm.clone(),
                nonce: master_key_nonce_new,
                salt: keyslot[0].salt,
            }];

            let header_new = Header {
                header_type: header.header_type,
                nonce: header.nonce,
                salt: header.salt,
                keyslots: Some(keyslots),
            };

            input_file
                .seek(std::io::SeekFrom::Current(-header_size))
                .context("Unable to seek back to the start of your input file")?;
            header_new.write(&mut input_file)?;

            success!("Key successfully updated for {}", input);
        }
        HeaderVersion::V5 => {
            let mut keyslots = header.keyslots.clone().unwrap();

            if keyslots.len() < 1 {
                return Err(anyhow::anyhow!("No keyslots found, so we cannot continue."));
            }

            match key_old {
                Key::User => info!("Please enter your old key below"),
                Key::Keyfile(_) => info!("Reading your old keyfile"),
                _ => (),
            }
            let raw_key_old = key_old.get_secret(&PasswordState::Direct)?;

            let mut index = 0;
            let mut master_key = [0u8; MASTER_KEY_LEN];

            // we need the index, so we can't use `decrypt_master_key()`
            for (i, keyslot) in keyslots.iter().enumerate() {
                let hash_start_time = Instant::now();
                let key_old = keyslot
                    .hash_algorithm
                    .hash(raw_key_old.clone(), &keyslot.salt)?;
                let hash_duration = hash_start_time.elapsed();
                success!(
                    "Successfully hashed your old key [took {:.2}s]",
                    hash_duration.as_secs_f32()
                );

                let cipher = Ciphers::initialize(key_old, &header.header_type.algorithm)?;

                let master_key_result =
                    cipher.decrypt(&keyslot.nonce, keyslot.encrypted_key.as_slice());

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
                return Err(anyhow::anyhow!("Unable to find a match with the key you provided (maybe you supplied the wrong key?)"));
            }

            let master_key = Protected::new(master_key);

            match key_new {
                Key::Generate => info!("Generating a new key"),
                Key::User => info!("Please enter your new key below"),
                Key::Keyfile(_) => info!("Reading your new keyfile"),
                Key::Env => (),
            }
            let raw_key_new = key_new.get_secret(&PasswordState::Validate)?;
            let salt_new = gen_salt();
            let hash_start_time = Instant::now();
            // TODO(brxken128): allow using argon2id/balloon/inherit
            let key_new = keyslots[index]
                .hash_algorithm
                .hash(raw_key_new, &salt_new)?;
            let hash_duration = hash_start_time.elapsed();
            success!(
                "Successfully hashed your new key [took {:.2}s]",
                hash_duration.as_secs_f32()
            );

            let cipher = Ciphers::initialize(key_new, &header.header_type.algorithm)?;

            let master_key_nonce_new = gen_nonce(&header.header_type.algorithm, &Mode::MemoryMode);
            let master_key_result =
                cipher.encrypt(&master_key_nonce_new, master_key.expose().as_slice());

            drop(master_key);

            let master_key_encrypted = master_key_result
                .map_err(|_| anyhow::anyhow!("Unable to encrypt your master key"))?;

            let mut master_key_encrypted_array = [0u8; ENCRYPTED_MASTER_KEY_LEN];

            let len = ENCRYPTED_MASTER_KEY_LEN.min(master_key_encrypted.len());
            master_key_encrypted_array[..len].copy_from_slice(&master_key_encrypted[..len]);

            // TODO(brxken128): allow using argon2id/balloon/inherit
            keyslots[index] = Keyslot {
                encrypted_key: master_key_encrypted_array,
                hash_algorithm: keyslots[index].hash_algorithm.clone(),
                nonce: master_key_nonce_new,
                salt: salt_new,
            };

            let header_new = Header {
                header_type: header.header_type,
                nonce: header.nonce,
                salt: None,
                keyslots: Some(keyslots),
            };

            input_file
                .seek(std::io::SeekFrom::Current(-header_size))
                .context("Unable to seek back to the start of your input file")?;
            header_new.write(&mut input_file)?;

            success!("Key successfully updated for {}", input);
        }
    }
    Ok(())
}

pub fn add_key(input: &str, key_old: &Key, key_new: &Key) -> Result<()> {
    let mut input_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(input)
        .with_context(|| format!("Unable to open input file: {}", input))?;

    let (header, _) = dexios_core::header::Header::deserialize(&mut input_file)?;

    let header_size: i64 = header
        .get_size()
        .try_into()
        .context("Unable to convert header size (u64) to i64")?;

    match header.header_type.version {
        HeaderVersion::V1 | HeaderVersion::V2 | HeaderVersion::V3 | HeaderVersion::V4 => {
            return Err(anyhow::anyhow!(
                "Adding a key is not supported in header versions below V5."
            ));
        }
        HeaderVersion::V5 => {
            let mut keyslots = header.keyslots.clone().unwrap();

            if keyslots.len() < 1 {
                return Err(anyhow::anyhow!("No keyslots found, so we cannot continue."));
            }

            if keyslots.len() >= 4 {
                return Err(anyhow::anyhow!("You have reached the maximum limit of keyslots (4) for this file! Please consider removing a keyslot or changing a key instead."));
            }

            match key_old {
                Key::User => info!("Please enter an old key below"),
                Key::Keyfile(_) => info!("Reading your old keyfile"),
                _ => (),
            }
            let raw_key_old = key_old.get_secret(&PasswordState::Direct)?;

            let master_key = dexios_core::key::decrypt_master_key(raw_key_old, &header)?;

            match key_new {
                Key::Generate => info!("Generating a new key"),
                Key::User => info!("Please enter your new key below"),
                Key::Keyfile(_) => info!("Reading your new keyfile"),
                Key::Env => (),
            }

            let raw_key_new = key_new.get_secret(&PasswordState::Validate)?;
            let salt_new = gen_salt();
            let hash_start_time = Instant::now();

            // TODO(brxken128): allow using argon2id/balloon/inherit
            let key_new = HashingAlgorithm::Blake3Balloon(5).hash(raw_key_new, &salt_new)?;
            let hash_duration = hash_start_time.elapsed();
            success!(
                "Successfully hashed your new key [took {:.2}s]",
                hash_duration.as_secs_f32()
            );

            let cipher = Ciphers::initialize(key_new, &header.header_type.algorithm)?;

            let master_key_nonce_new = gen_nonce(&header.header_type.algorithm, &Mode::MemoryMode);
            let master_key_result =
                cipher.encrypt(&master_key_nonce_new, master_key.expose().as_slice());

            drop(master_key);

            let master_key_encrypted = master_key_result
                .map_err(|_| anyhow::anyhow!("Unable to encrypt your master key"))?;

            let mut master_key_encrypted_array = [0u8; ENCRYPTED_MASTER_KEY_LEN];

            let len = ENCRYPTED_MASTER_KEY_LEN.min(master_key_encrypted.len());
            master_key_encrypted_array[..len].copy_from_slice(&master_key_encrypted[..len]);

            // TODO(brxken128): allow using argon2id/balloon/inherit
            let keyslot_new = Keyslot {
                encrypted_key: master_key_encrypted_array,
                hash_algorithm: HashingAlgorithm::Blake3Balloon(5),
                nonce: master_key_nonce_new,
                salt: salt_new,
            };

            keyslots.push(keyslot_new);

            let header_new = Header {
                header_type: header.header_type,
                nonce: header.nonce,
                salt: None,
                keyslots: Some(keyslots),
            };

            input_file
                .seek(std::io::SeekFrom::Current(-header_size))
                .context("Unable to seek back to the start of your input file")?;
            header_new.write(&mut input_file)?;

            success!("Key successfully added for {}", input);
        }
    }
    Ok(())
}

pub fn del_key(input: &str, key: &Key) -> Result<()> {
    let mut input_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(input)
        .with_context(|| format!("Unable to open input file: {}", input))?;

    let (header, _) = dexios_core::header::Header::deserialize(&mut input_file)?;

    let header_size: i64 = header
        .get_size()
        .try_into()
        .context("Unable to convert header size (u64) to i64")?;

    match header.header_type.version {
        HeaderVersion::V1 | HeaderVersion::V2 | HeaderVersion::V3 | HeaderVersion::V4 => {
            return Err(anyhow::anyhow!(
                "Deleting a key is not supported in header versions below V5."
            ));
        }
        HeaderVersion::V5 => {
            let mut keyslots = header.keyslots.clone().unwrap();

            if keyslots.len() == 1 {
                // TODO(brxken128): add a prompt to the user to see if they'd like to continue
                return Err(anyhow::anyhow!(
                    "Only 1 keyslot detected! Removing this key will make this file un-decryptable. Please consider stripping the header instead."
                ));
            } else if keyslots.len() < 1 {
                return Err(anyhow::anyhow!("No keyslots found, so we cannot continue."));
            }

            let raw_key = key.get_secret(&PasswordState::Direct)?;

            let mut index = 0;
            let mut master_key = [0u8; MASTER_KEY_LEN];

            // we need the index, so we can't use `decrypt_master_key()`
            for (i, keyslot) in keyslots.iter().enumerate() {
                let hash_start_time = Instant::now();
                let key_old = keyslot
                    .hash_algorithm
                    .hash(raw_key.clone(), &keyslot.salt)?;
                let hash_duration = hash_start_time.elapsed();
                success!(
                    "Successfully hashed your old key [took {:.2}s]",
                    hash_duration.as_secs_f32()
                );

                let cipher = Ciphers::initialize(key_old, &header.header_type.algorithm)?;

                let master_key_result =
                    cipher.decrypt(&keyslot.nonce, keyslot.encrypted_key.as_slice());

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
                return Err(anyhow::anyhow!("Unable to find a match with the key you provided (maybe you supplied the wrong key?)"));
            }

            keyslots.remove(index);

            let header_new = Header {
                header_type: header.header_type,
                nonce: header.nonce,
                salt: None,
                keyslots: Some(keyslots),
            };

            input_file
                .seek(std::io::SeekFrom::Current(-header_size))
                .context("Unable to seek back to the start of your input file")?;
            header_new.write(&mut input_file)?;

            success!("Key successfully updated for {}", input);
        }
    }
    Ok(())
}
